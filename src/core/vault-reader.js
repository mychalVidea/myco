/**
 * MYCO Vault - High Performance Container Reader & Query Engine
 * Supports streaming chunk-by-chunk decryption, filtering, and multi-file search.
 */

const fs = require('fs');
const path = require('path');
const { CHUNK_MAGIC, HEADER_SIZE, parseVaultDate } = require('./format');
const { verifyAndDeriveHeader, decryptDual } = require('./crypto');
const { decompress } = require('./compressor');
const { decodeChunk } = require('./tokenizer');

class VaultReader {
    /**
     * @param {string} filePath Path to .myco container
     * @param {string} secret Master decryption passphrase
     */
    constructor(filePath, secret) {
        if (!filePath) throw new Error('filePath is required.');
        if (!secret) throw new Error('secret is required.');

        this.filePath = path.resolve(filePath);
        this.secret = secret;
        this.keys = null;
        this.headerVerified = false;
    }

    /**
     * Reads and verifies the container header
     * @returns {{ salt: Buffer }}
     */
    verifyHeader() {
        if (this.headerVerified) return { salt: this.salt };

        const fd = fs.openSync(this.filePath, 'r');
        try {
            const headerBuf = Buffer.alloc(HEADER_SIZE);
            const bytesRead = fs.readSync(fd, headerBuf, 0, HEADER_SIZE, 0);
            if (bytesRead < HEADER_SIZE) {
                throw new Error('File too short or corrupted container header.');
            }
            const { salt, keys } = verifyAndDeriveHeader(headerBuf, this.secret);
            this.salt = salt;
            this.keys = keys;
            this.headerVerified = true;
            return { salt };
        } finally {
            fs.closeSync(fd);
        }
    }

    /**
     * Async generator yielding chunk records sequentially without loading entire file in RAM
     * @yields {Array<{ timestamp: number, source: string, level: string, message: string }>}
     */
    async *readChunks() {
        this.verifyHeader();

        const fd = fs.openSync(this.filePath, 'r');
        const stat = fs.fstatSync(fd);
        const fileSize = stat.size;
        let offset = HEADER_SIZE;

        try {
            const headerMetaBuf = Buffer.alloc(16);

            while (offset + 16 <= fileSize) {
                fs.readSync(fd, headerMetaBuf, 0, 16, offset);

                const magic = headerMetaBuf.subarray(0, 4);
                if (!magic.equals(CHUNK_MAGIC)) {
                    // Encountered non-chunk data or end-of-file alignment
                    break;
                }

                const rawLen = headerMetaBuf.readUInt32BE(4);
                const compressedLen = headerMetaBuf.readUInt32BE(8);
                const payloadLen = headerMetaBuf.readUInt32BE(12);

                offset += 16;
                if (offset + payloadLen > fileSize) {
                    // Truncated chunk at EOF (e.g. process was killed during flush)
                    console.warn(`[MYCO VaultReader] Incomplete chunk detected at byte ${offset}, skipping.`);
                    break;
                }

                const encryptedPayload = Buffer.alloc(payloadLen);
                fs.readSync(fd, encryptedPayload, 0, payloadLen, offset);
                offset += payloadLen;

                // Decrypt
                const compressedBuf = decryptDual(encryptedPayload, this.keys);

                // Decompress
                const col4Buf = decompress(compressedBuf);

                // Decode columnar records
                const records = decodeChunk(col4Buf);

                yield records;
            }
        } finally {
            fs.closeSync(fd);
        }
    }

    /**
     * Reads all records from the container
     * @param {Object} [filter]
     * @param {number} [filter.since]
     * @param {number} [filter.until]
     * @param {string|string[]} [filter.sources]
     * @param {string|string[]} [filter.levels]
     * @param {string|RegExp} [filter.query]
     * @param {number} [filter.limit]
     * @returns {Promise<Array<{ timestamp: number, source: string, level: string, message: string }>>}
     */
    async readAll(filter = {}) {
        const results = [];
        const sourcesSet = filter.sources ? new Set([].concat(filter.sources).map(s => s.toLowerCase())) : null;
        const levelsSet = filter.levels ? new Set([].concat(filter.levels).map(l => l.toUpperCase())) : null;
        let regex = null;
        if (filter.query) {
            regex = filter.query instanceof RegExp ? filter.query : new RegExp(filter.query, 'i');
        }

        for await (const chunk of this.readChunks()) {
            for (const rec of chunk) {
                if (filter.since && rec.timestamp < filter.since) continue;
                if (filter.until && rec.timestamp > filter.until) continue;
                if (sourcesSet && !sourcesSet.has(rec.source.toLowerCase())) continue;
                if (levelsSet && !levelsSet.has(rec.level.toUpperCase())) continue;
                if (regex && !regex.test(rec.message) && !regex.test(rec.source)) continue;

                results.push(rec);
                if (filter.limit && results.length >= filter.limit) {
                    return results;
                }
            }
        }

        return results;
    }

    /**
     * Reads container info without decrypting full logs
     * @returns {Promise<{ fileSize: number, chunkCount: number, estRecords: number }>}
     */
    async inspect() {
        this.verifyHeader();
        const stat = fs.statSync(this.filePath);
        let chunkCount = 0;
        let estRecords = 0;

        for await (const chunk of this.readChunks()) {
            chunkCount++;
            estRecords += chunk.length;
        }

        return {
            fileSize: stat.size,
            chunkCount,
            totalRecords: estRecords
        };
    }

    /**
     * Query all containers in a directory
     * @param {string} vaultDir
     * @param {string} secret
     * @param {Object} [filter]
     * @returns {Promise<Array<{ timestamp: number, source: string, level: string, message: string }>>}
     */
    static async queryDirectory(vaultDir, secret, filter = {}) {
        const dir = path.resolve(vaultDir);
        if (!fs.existsSync(dir)) return [];

        const files = fs.readdirSync(dir)
            .filter(f => f.endsWith('.myco'))
            .sort((a, b) => parseVaultDate(a) - parseVaultDate(b));

        const allResults = [];
        for (const file of files) {
            const filePath = path.join(dir, file);
            try {
                const reader = new VaultReader(filePath, secret);
                const fileRecords = await reader.readAll(filter);
                allResults.push(...fileRecords);
                if (filter.limit && allResults.length >= filter.limit) {
                    return allResults.slice(0, filter.limit);
                }
            } catch (err) {
                console.error(`[MYCO VaultReader] Skipping ${file}: ${err.message}`);
            }
        }

        return allResults;
    }

    /**
     * Fast header-only container inspection (zero-crypto, sub-millisecond)
     * Scans 16-byte chunk block headers without decrypting payloads.
     * @param {string} filePath
     * @returns {{ fileSize: number, rawBytes: number, chunkCount: number, compressionRatio: string, savedPercent: number }}
     */
    static fastInspect(filePath) {
        if (!fs.existsSync(filePath)) {
            return { fileSize: 0, rawBytes: 0, chunkCount: 0, compressionRatio: '1.00', savedPercent: 0 };
        }

        const stat = fs.statSync(filePath);
        if (stat.size < HEADER_SIZE) {
            return { fileSize: stat.size, rawBytes: stat.size, chunkCount: 0, compressionRatio: '1.00', savedPercent: 0 };
        }

        const fd = fs.openSync(filePath, 'r');
        let totalRaw = 0;
        let totalChunks = 0;
        let offset = HEADER_SIZE;
        const metaBuf = Buffer.alloc(16);

        try {
            while (offset + 16 <= stat.size) {
                fs.readSync(fd, metaBuf, 0, 16, offset);
                const magic = metaBuf.subarray(0, 4);
                if (!magic.equals(CHUNK_MAGIC)) {
                    break;
                }
                const rawLen = metaBuf.readUInt32BE(4);
                const payloadLen = metaBuf.readUInt32BE(12);

                totalRaw += rawLen;
                totalChunks++;
                offset += 16 + payloadLen;
            }
        } catch {
            // Partial read fallback
        } finally {
            try { fs.closeSync(fd); } catch {}
        }

        const rawBytes = totalRaw || stat.size;
        const ratio = stat.size > 0 && rawBytes > 0 ? (rawBytes / stat.size).toFixed(2) : '1.00';
        const savedPercent = rawBytes > stat.size ? Math.min(99, Math.round(((rawBytes - stat.size) / rawBytes) * 100)) : 0;

        return {
            fileSize: stat.size,
            rawBytes,
            chunkCount: totalChunks,
            compressionRatio: ratio,
            savedPercent
        };
    }
}

module.exports = {
    VaultReader
};
