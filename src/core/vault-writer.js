/**
 * MYCO Vault - High Performance Container Writer
 * Handles automatic file rotation, chunk batching, compression, and Dual AEAD encryption.
 */

const fs = require('fs');
const path = require('path');
const { CHUNK_MAGIC, HEADER_SIZE, formatVaultFilename } = require('./format');
const { createContainerHeader } = require('./crypto');
const { compress } = require('./compressor');
const { encodeChunk } = require('./tokenizer');

class VaultWriter {
    /**
     * @param {Object} options
     * @param {string} options.vaultDir Directory where .myco containers will be saved
     * @param {string} options.secret Master encryption passphrase
     * @param {'daily'|'hourly'} [options.rotation='daily']
     * @param {number} [options.flushIntervalMs=5000]
     * @param {number} [options.maxBatchRecords=500]
     * @param {number} [options.maxBatchBytes=65536]
     * @param {'fast'|'balanced'|'max'} [options.compressMode='fast']
     */
    constructor(options = {}) {
        if (!options.vaultDir) throw new Error('vaultDir is required.');
        if (!options.secret) throw new Error('secret is required.');

        this.vaultDir = path.resolve(options.vaultDir);
        this.secret = options.secret;
        this.rotation = options.rotation || 'daily';
        this.flushIntervalMs = options.flushIntervalMs || 5000;
        this.maxBatchRecords = options.maxBatchRecords || 500;
        this.maxBatchBytes = options.maxBatchBytes || 65536;
        this.compressMode = options.compressMode || 'fast';
        this.fileName = options.fileName || null;

        this.buffer = [];
        this.bufferedBytes = 0;
        this.flushTimer = null;
        this.isFlushing = false;
        this.closed = false;

        this.activeFileName = this.fileName;
        this.activeFilePath = this.fileName ? path.join(this.vaultDir, this.fileName) : null;
        this.activeKeys = null;
        this.activeFd = null;

        // Statistics
        this.stats = {
            totalRecords: 0,
            rawBytes: 0,
            storedBytes: 0,
            chunksWritten: 0
        };

        if (!fs.existsSync(this.vaultDir)) {
            fs.mkdirSync(this.vaultDir, { recursive: true });
        }

        this._startFlushTimer();
    }

    _startFlushTimer() {
        if (this.flushTimer) clearInterval(this.flushTimer);
        this.flushTimer = setInterval(() => {
            if (this.buffer.length > 0 && !this.isFlushing) {
                this.flush();
            }
        }, this.flushIntervalMs);
        if (this.flushTimer.unref) this.flushTimer.unref();
    }

    /**
     * Add a record to the writer buffer
     * @param {Object} record { timestamp, source, level, message }
     */
    write(record) {
        if (this.closed) return;
        const rec = {
            timestamp: record.timestamp || Date.now(),
            source: record.source || 'default',
            level: record.level || 'INFO',
            message: record.message || ''
        };

        this.buffer.push(rec);
        const estBytes = rec.message.length + rec.source.length + 16;
        this.bufferedBytes += estBytes;

        if (this.buffer.length >= this.maxBatchRecords || this.bufferedBytes >= this.maxBatchBytes) {
            this.flush();
        }
    }

    /**
     * Ensure the active file container matches current rotation period
     */
    _ensureContainer() {
        const expectedName = this.fileName || formatVaultFilename(new Date(), this.rotation);
        if (this.activeFileName === expectedName && this.activeFd !== null) {
            return;
        }

        // Close previous file if rotating
        if (this.activeFd !== null) {
            try {
                fs.closeSync(this.activeFd);
            } catch {}
            this.activeFd = null;
        }

        this.activeFileName = expectedName;
        this.activeFilePath = path.join(this.vaultDir, expectedName);

        const fileExists = fs.existsSync(this.activeFilePath);

        if (!fileExists) {
            // Create container with new header
            const { header, keys } = createContainerHeader(this.secret);
            this.activeKeys = keys;
            this.activeFd = fs.openSync(this.activeFilePath, 'w+');
            fs.writeSync(this.activeFd, header, 0, header.length, 0);
        } else {
            // Open existing file and verify header
            const { verifyAndDeriveHeader } = require('./crypto');
            const fd = fs.openSync(this.activeFilePath, 'r+');
            const headerBuf = Buffer.alloc(HEADER_SIZE);
            fs.readSync(fd, headerBuf, 0, HEADER_SIZE, 0);
            const { keys } = verifyAndDeriveHeader(headerBuf, this.secret);
            this.activeKeys = keys;
            this.activeFd = fd;
        }
    }

    /**
     * Flush buffered records into a compressed & encrypted chunk
     */
    flush() {
        if (this.buffer.length === 0 || this.isFlushing) return;
        this.isFlushing = true;

        const records = this.buffer;
        this.buffer = [];
        this.bufferedBytes = 0;

        try {
            this._ensureContainer();

            // 1. Columnar encode
            const col4Buf = encodeChunk(records);
            const rawLen = col4Buf.length;

            // 2. Compress with Brotli
            const compressed = compress(col4Buf, { mode: this.compressMode });

            // 3. Encrypt Dual AEAD
            const { encryptDual } = require('./crypto');
            const encrypted = encryptDual(compressed, this.activeKeys);

            // 4. Assemble Chunk Block:
            // [MAGIC (4B)] [RAW_LEN (4B)] [COMPRESSED_LEN (4B)] [PAYLOAD_LEN (4B)] [ENCRYPTED_PAYLOAD]
            const chunkHeader = Buffer.alloc(16);
            CHUNK_MAGIC.copy(chunkHeader, 0);
            chunkHeader.writeUInt32BE(rawLen, 4);
            chunkHeader.writeUInt32BE(compressed.length, 8);
            chunkHeader.writeUInt32BE(encrypted.length, 12);

            const block = Buffer.concat([chunkHeader, encrypted]);

            // Append to file
            const stat = fs.fstatSync(this.activeFd);
            fs.writeSync(this.activeFd, block, 0, block.length, stat.size);

            this.stats.totalRecords += records.length;
            this.stats.rawBytes += rawLen;
            this.stats.storedBytes += block.length;
            this.stats.chunksWritten++;
        } catch (err) {
            console.error('[MYCO VaultWriter] Flush error:', err);
            // Re-queue unwritten records to avoid data loss
            this.buffer = records.concat(this.buffer);
        } finally {
            this.isFlushing = false;
        }
    }

    /**
     * Close the writer and flush remaining logs
     */
    close() {
        this.closed = true;
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        this.flush();
        if (this.activeFd !== null) {
            try {
                fs.closeSync(this.activeFd);
            } catch {}
            this.activeFd = null;
        }
    }
}

module.exports = {
    VaultWriter
};
