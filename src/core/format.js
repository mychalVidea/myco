/**
 * MYCO Vault - Binary Format Definitions & Index Helper
 * Zero-dependency log container standard.
 */

const FILE_MAGIC = Buffer.from('MYCO', 'utf8'); // 4 bytes
const CHUNK_MAGIC = Buffer.from('CBLK', 'utf8'); // 4 bytes
const FORMAT_VERSION = 1; // 1 byte
const SALT_SIZE = 16; // 16 bytes random salt per vault container
const CHECK_TAG_SIZE = 16; // 16 bytes verification tag for password validation
const HEADER_SIZE = 4 + 1 + SALT_SIZE + CHECK_TAG_SIZE; // 37 bytes total

/**
 * Format daily filename for container
 * @param {Date} [date]
 * @returns {string} e.g. "vault-2026-09-22.myco"
 */
function formatVaultFilename(date = new Date(), rotation = 'daily') {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    if (rotation === 'hourly') {
        const h = String(date.getHours()).padStart(2, '0');
        return `vault-${y}-${m}-${d}-${h}.myco`;
    }
    return `vault-${y}-${m}-${d}.myco`;
}

/**
 * Parses timestamp from vault filename for chronological sorting
 * @param {string} fileName
 * @returns {number} Unix timestamp in ms
 */
function parseVaultDate(fileName) {
    if (!fileName) return 0;
    const mHourly = fileName.match(/^vault-(\d{4})-(\d{2})-(\d{2})-(\d{2})\.myco$/);
    if (mHourly) {
        return new Date(parseInt(mHourly[1], 10), parseInt(mHourly[2], 10) - 1, parseInt(mHourly[3], 10), parseInt(mHourly[4], 10)).getTime();
    }
    const mDaily = fileName.match(/^vault-(\d{4})-(\d{2})-(\d{2})\.myco$/);
    if (mDaily) {
        return new Date(parseInt(mDaily[1], 10), parseInt(mDaily[2], 10) - 1, parseInt(mDaily[3], 10)).getTime();
    }
    // Backward compatibility with log-DD-MM-YYYY.myco
    const mOld = fileName.match(/^log-(\d+)-(\d+)-(\d{4})\.myco$/);
    if (mOld) {
        return new Date(parseInt(mOld[3], 10), parseInt(mOld[2], 10) - 1, parseInt(mOld[1], 10)).getTime();
    }
    return 0;
}

module.exports = {
    FILE_MAGIC,
    CHUNK_MAGIC,
    FORMAT_VERSION,
    SALT_SIZE,
    CHECK_TAG_SIZE,
    HEADER_SIZE,
    formatVaultFilename,
    parseVaultDate
};
