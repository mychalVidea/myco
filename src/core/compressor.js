/**
 * MYCO Vault - High Performance Brotli Compression Engine
 * Zero-dependency: Native Node.js zlib implementation.
 */

const zlib = require('zlib');

/**
 * Compresses a buffer with Brotli algorithm
 * @param {Buffer} buffer Input data
 * @param {Object} [options]
 * @param {'fast'|'balanced'|'max'} [options.mode='balanced']
 * @param {number} [options.quality] 0-11
 * @param {number} [options.lgwin] 10-24
 * @returns {Buffer} Compressed buffer
 */
function compress(buffer, options = {}) {
    if (!buffer || buffer.length === 0) return Buffer.alloc(0);

    let quality = 8;
    let lgwin = 22;

    if (options.mode === 'fast') {
        quality = 6;
        lgwin = 20;
    } else if (options.mode === 'max' || options.highQuality) {
        quality = 11;
        lgwin = 24;
    }

    if (options.quality !== undefined) quality = Math.min(11, Math.max(0, options.quality));
    if (options.lgwin !== undefined) lgwin = Math.min(24, Math.max(10, options.lgwin));

    return zlib.brotliCompressSync(buffer, {
        params: {
            [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_GENERIC,
            [zlib.constants.BROTLI_PARAM_QUALITY]: quality,
            [zlib.constants.BROTLI_PARAM_LGWIN]: lgwin,
            [zlib.constants.BROTLI_PARAM_SIZE_HINT]: buffer.length
        }
    });
}

/**
 * Decompresses a Brotli compressed buffer
 * @param {Buffer} compressedBuffer
 * @returns {Buffer} Decompressed buffer
 */
function decompress(compressedBuffer) {
    if (!compressedBuffer || compressedBuffer.length === 0) return Buffer.alloc(0);
    return zlib.brotliDecompressSync(compressedBuffer);
}

module.exports = {
    compress,
    decompress
};
