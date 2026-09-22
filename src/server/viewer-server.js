/**
 * MYCO Vault - Embedded Zero-Dependency Web Viewer & API
 * Provides live log search, file inspection, decryption, and packing via native Node.js HTTP.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { VaultReader } = require('../core/vault-reader');
const { VaultWriter } = require('../core/vault-writer');
const { parseVaultDate, formatVaultFilename } = require('../core/format');

class ViewerServer {
    /**
     * @param {Object} options
     * @param {number} [options.port=8088]
     * @param {string} [options.host='127.0.0.1']
     * @param {string} options.vaultDir
     * @param {string} [options.defaultSecret]
     */
    constructor(options = {}) {
        this.port = options.port || 8088;
        this.host = options.host || '127.0.0.1';
        this.vaultDir = path.resolve(options.vaultDir || './vault');
        this.defaultSecret = options.defaultSecret || '';
        this.server = null;
        this.publicDir = path.join(__dirname, '../../public');
        this.subscribers = new Set();
    }

    start() {
        this.server = http.createServer((req, res) => this._handleRequest(req, res));
        return new Promise((resolve, reject) => {
            this.server.listen(this.port, this.host, () => {
                console.log(`[MYCO Web Viewer] UI active at: http://${this.host}:${this.port}`);
                resolve(`http://${this.host}:${this.port}`);
            });
            this.server.on('error', reject);
        });
    }

    stop() {
        if (this.server) {
            this.server.close();
            this.server = null;
        }
    }

    /**
     * Broadcast live record to SSE subscribers
     */
    broadcastRecord(record) {
        if (this.subscribers.size === 0) return;
        const data = `data: ${JSON.stringify(record)}\n\n`;
        for (const res of this.subscribers) {
            try {
                res.write(data);
            } catch {
                this.subscribers.delete(res);
            }
        }
    }

    async _handleRequest(req, res) {
        const parsedUrl = url.parse(req.url, true);
        const pathname = parsedUrl.pathname;

        // Security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');

        // CORS for local development
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Vault-Secret');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }

        try {
            // API Routes
            if (pathname === '/api/status' && req.method === 'GET') {
                return this._handleStatus(req, res);
            }
            if (pathname === '/api/query' && req.method === 'POST') {
                return await this._handleQuery(req, res);
            }
            if (pathname === '/api/stream' && req.method === 'GET') {
                return this._handleStream(req, res);
            }
            if (pathname === '/api/pack' && req.method === 'POST') {
                return await this._handlePack(req, res);
            }
            if (pathname === '/api/unpack' && req.method === 'POST') {
                return await this._handleUnpack(req, res);
            }

            // Static files
            this._serveStatic(pathname, res);
        } catch (err) {
            console.error('[MYCO Server Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
    }

    _serveStatic(pathname, res) {
        let filePath = path.join(this.publicDir, pathname === '/' ? 'index.html' : pathname);

        if (!filePath.startsWith(this.publicDir)) {
            res.writeHead(403);
            return res.end('Forbidden');
        }

        if (!fs.existsSync(filePath)) {
            filePath = path.join(this.publicDir, 'index.html');
        }

        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.json': 'application/json; charset=utf-8',
            '.png': 'image/png',
            '.svg': 'image/svg+xml'
        };

        const contentType = mimeTypes[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        fs.createReadStream(filePath).pipe(res);
    }

    _handleStatus(req, res) {
        let files = [];
        let totalSize = 0;
        let totalRaw = 0;
        const todayStr = formatVaultFilename(new Date(), 'daily');

        if (fs.existsSync(this.vaultDir)) {
            files = fs.readdirSync(this.vaultDir)
                .filter(f => f.endsWith('.myco'))
                .map(f => {
                    const filePath = path.join(this.vaultDir, f);
                    const stat = fs.statSync(filePath);
                    const info = VaultReader.fastInspect(filePath);
                    totalSize += stat.size;
                    totalRaw += info.rawBytes;
                    const isToday = f === todayStr;

                    return {
                        name: f,
                        size: stat.size,
                        rawBytes: info.rawBytes,
                        chunkCount: info.chunkCount,
                        compressionRatio: info.compressionRatio,
                        savedPercent: info.savedPercent,
                        isToday,
                        modified: stat.mtimeMs,
                        date: parseVaultDate(f)
                    };
                })
                .sort((a, b) => b.modified - a.modified);
        }

        const totalSaved = Math.max(0, totalRaw - totalSize);
        const overallRatio = totalSize > 0 && totalRaw > 0 ? (totalRaw / totalSize).toFixed(2) : '1.00';
        const overallSavedPercent = totalRaw > 0 ? Math.min(99, Math.round((totalSaved / totalRaw) * 100)) : 0;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            vaultDir: this.vaultDir,
            hasDefaultSecret: !!this.defaultSecret,
            fileCount: files.length,
            totalSizeBytes: totalSize,
            totalRawBytes: totalRaw,
            totalSavedBytes: totalSaved,
            overallRatio,
            overallSavedPercent,
            files
        }));
    }

    async _handleQuery(req, res) {
        const body = await this._readJsonBody(req);
        const secret = body.secret || req.headers['x-vault-secret'] || this.defaultSecret;

        if (!secret) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Decryption secret is required.' }));
        }

        const filter = {
            since: body.since ? Number(body.since) : undefined,
            until: body.until ? Number(body.until) : undefined,
            sources: body.sources,
            levels: body.levels,
            query: body.query,
            limit: body.limit ? Math.min(Number(body.limit), 5000) : 500
        };

        try {
            let records = [];
            if (body.file) {
                const targetPath = path.join(this.vaultDir, path.basename(body.file));
                const reader = new VaultReader(targetPath, secret);
                records = await reader.readAll(filter);
            } else {
                records = await VaultReader.queryDirectory(this.vaultDir, secret, filter);
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                count: records.length,
                records
            }));
        } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Query failed: ${err.message}` }));
        }
    }

    _handleStream(req, res) {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });

        res.write('retry: 2000\n\n');
        this.subscribers.add(res);

        req.on('close', () => {
            this.subscribers.delete(res);
        });
    }

    async _handlePack(req, res) {
        const body = await this._readJsonBody(req);
        const secret = body.secret || this.defaultSecret;
        const text = body.content || '';
        const sourceName = body.source || 'manual';

        if (!secret) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Secret is required to encrypt container.' }));
        }

        const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
        const tempContainer = path.join(this.vaultDir, `pack-${Date.now()}.myco`);
        const tempDir = path.dirname(tempContainer);

        const writer = new VaultWriter({
            vaultDir: tempDir,
            secret: secret,
            rotation: 'daily',
            flushIntervalMs: 100
        });

        for (const line of lines) {
            writer.write({
                timestamp: Date.now(),
                source: sourceName,
                message: line
            });
        }
        writer.close();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            success: true,
            recordsPacked: lines.length,
            fileName: writer.activeFileName
        }));
    }

    async _handleUnpack(req, res) {
        const body = await this._readJsonBody(req);
        const secret = body.secret || this.defaultSecret;
        const fileName = body.file;

        if (!secret || !fileName) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Secret and file are required.' }));
        }

        const targetPath = path.join(this.vaultDir, path.basename(fileName));
        const reader = new VaultReader(targetPath, secret);
        const records = await reader.readAll();

        const plainText = records.map(r => {
            const time = new Date(r.timestamp).toISOString();
            return `[${time}] [${r.source}] [${r.level}] ${r.message}`;
        }).join('\n');

        res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename="${path.basename(fileName, '.myco')}.log"`
        });
        res.end(plainText);
    }

    _readJsonBody(req) {
        return new Promise((resolve, reject) => {
            let data = '';
            req.on('data', chunk => {
                data += chunk;
                if (data.length > 50 * 1024 * 1024) { // 50MB max body
                    req.destroy();
                    reject(new Error('Payload too large'));
                }
            });
            req.on('end', () => {
                try {
                    resolve(data ? JSON.parse(data) : {});
                } catch (e) {
                    reject(new Error('Invalid JSON format'));
                }
            });
            req.on('error', reject);
        });
    }
}

module.exports = {
    ViewerServer
};
