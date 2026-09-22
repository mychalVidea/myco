/**
 * MYCO Vault - Zero-Dependency Encrypted Log Container & Real-Time Log Manager
 * 
 * Features:
 * - Dual-layer AEAD encryption (AES-256-GCM + ChaCha20-Poly1305) with HKDF-SHA512
 * - High-ratio Brotli compression
 * - COL4 Columnar binary format with LEB128 varints and dynamic dictionary
 * - Zero external runtime dependencies (Native Node.js crypto, zlib, fs, http)
 * - Standalone CLI, Daemon, and Embedded Web Viewer UI
 */

const fs = require('fs');
const path = require('path');
const { VaultWriter } = require('./core/vault-writer');
const { VaultReader } = require('./core/vault-reader');
const { Collector } = require('./collector/watcher');
const { ViewerServer } = require('./server/viewer-server');
const crypto = require('./core/crypto');
const compressor = require('./core/compressor');
const tokenizer = require('./core/tokenizer');
const format = require('./core/format');

/**
 * Packs a raw log file, directory of logs, or raw string into an encrypted .myco container
 * @param {string} inputPath File path, directory path, or raw log text
 * @param {string} outVaultPath Destination .myco container file or directory
 * @param {string} secret Master encryption secret key
 * @param {Object} [options]
 * @param {string} [options.source='manual'] Log source identifier
 * @param {'fast'|'balanced'|'max'} [options.compressMode='balanced']
 * @returns {Promise<{ vaultPath: string, recordsPacked: number, rawBytes: number, storedBytes: number }>}
 */
async function packFiles(inputPath, outVaultPath, secret, options = {}) {
    if (!inputPath) throw new Error('inputPath is required.');
    if (!outVaultPath) throw new Error('outVaultPath is required.');
    if (!secret) throw new Error('secret is required.');

    const sourceName = options.source || 'import';
    const hasMycoExt = path.extname(outVaultPath).toLowerCase() === '.myco';
    const isDirOut = !hasMycoExt || (fs.existsSync(outVaultPath) && fs.statSync(outVaultPath).isDirectory());
    const vaultDir = isDirOut ? path.resolve(outVaultPath) : path.dirname(path.resolve(outVaultPath));
    const targetFileName = isDirOut ? format.formatVaultFilename(new Date(), 'daily') : path.basename(outVaultPath);

    if (!fs.existsSync(vaultDir)) {
        fs.mkdirSync(vaultDir, { recursive: true });
    }

    const finalVaultPath = path.join(vaultDir, targetFileName);

    const writer = new VaultWriter({
        vaultDir,
        secret,
        rotation: 'daily',
        fileName: targetFileName,
        flushIntervalMs: 100,
        compressMode: options.compressMode || 'balanced'
    });

    let recordsPacked = 0;

    // Check if input is an existing path
    if (fs.existsSync(inputPath)) {
        const stat = fs.statSync(inputPath);
        const filesToProcess = [];

        if (stat.isDirectory()) {
            const list = fs.readdirSync(inputPath);
            for (const f of list) {
                const full = path.join(inputPath, f);
                if (fs.statSync(full).isFile() && (f.endsWith('.log') || f.endsWith('.txt'))) {
                    filesToProcess.push({ full, name: path.basename(f, path.extname(f)) });
                }
            }
        } else {
            filesToProcess.push({ full: inputPath, name: sourceName });
        }

        for (const item of filesToProcess) {
            const content = fs.readFileSync(item.full, 'utf8');
            const lines = content.split(/\r?\n/);
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                writer.write({
                    timestamp: Date.now(),
                    source: item.name,
                    message: trimmed
                });
                recordsPacked++;
            }
        }
    } else {
        // Treat inputPath as raw string content
        const lines = inputPath.split(/\r?\n/);
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            writer.write({
                timestamp: Date.now(),
                source: sourceName,
                message: trimmed
            });
            recordsPacked++;
        }
    }

    writer.close();

    const resultStat = fs.existsSync(finalVaultPath) ? fs.statSync(finalVaultPath) : { size: 0 };

    return {
        vaultPath: finalVaultPath,
        recordsPacked,
        rawBytes: writer.stats.rawBytes,
        storedBytes: resultStat.size
    };
}

/**
 * Decrypts and unpacks a .myco container into a plain-text .log file or returns records
 * @param {string} vaultFilePath Path to .myco container
 * @param {string} [outDestination] Output directory or .log file path (optional)
 * @param {string} secret Master decryption passphrase
 * @returns {Promise<{ records: Array<Object>, outputPath: string|null, extractedLines: number }>}
 */
async function unpackVault(vaultFilePath, outDestination, secret) {
    if (!vaultFilePath) throw new Error('vaultFilePath is required.');
    if (!secret) throw new Error('secret is required.');

    const reader = new VaultReader(vaultFilePath, secret);
    const records = await reader.readAll();

    let outputPath = null;
    if (outDestination) {
        let dest = path.resolve(outDestination);
        if (fs.existsSync(dest) && fs.statSync(dest).isDirectory()) {
            const baseName = path.basename(vaultFilePath, '.myco');
            dest = path.join(dest, `${baseName}.log`);
        }

        const outDir = path.dirname(dest);
        if (!fs.existsSync(outDir)) {
            fs.mkdirSync(outDir, { recursive: true });
        }

        const lines = records.map(r => {
            const iso = new Date(r.timestamp).toISOString();
            return `[${iso}] [${r.source}] [${r.level}] ${r.message}`;
        });

        fs.writeFileSync(dest, lines.join('\n') + (lines.length > 0 ? '\n' : ''), 'utf8');
        outputPath = dest;
    }

    return {
        records,
        outputPath,
        extractedLines: records.length
    };
}

/**
 * High level search across vault files
 * @param {string} vaultDir
 * @param {string} secret
 * @param {Object} [filter]
 */
async function queryVault(vaultDir, secret, filter = {}) {
    return VaultReader.queryDirectory(vaultDir, secret, filter);
}

module.exports = {
    VaultWriter,
    VaultReader,
    Collector,
    ViewerServer,
    packFiles,
    unpackVault,
    queryVault,
    generateKey: crypto.generateRandomKey,
    crypto,
    compressor,
    tokenizer,
    format
};
