/**
 * MYCO Vault - Dual Layer AEAD Cryptographic Engine
 * Zero-dependency: Uses Node.js native crypto module.
 * 
 * Layers:
 * 1. Inner: AES-256-GCM (Hardware accelerated AES-NI)
 * 2. Outer: ChaCha20-Poly1305 (Constant-time stream cipher)
 * 
 * Keys derived via HKDF-SHA512 from master secret + container salt.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { FILE_MAGIC, SALT_SIZE, CHECK_TAG_SIZE } = require('./format');

const VERIFY_STRING = Buffer.from('MYCO_KEY_VERIFY_V1', 'utf8');

/**
 * Derives encryption keys from master secret and salt using HKDF-SHA512
 * @param {string|Buffer} masterSecret
 * @param {Buffer} salt 16-byte salt
 * @returns {{ keyAes: Buffer, keyChaCha: Buffer, checkTag: Buffer }}
 */
function deriveVaultKeys(masterSecret, salt) {
    if (!masterSecret) {
        throw new Error('Master secret is required for key derivation.');
    }
    const secretBuf = Buffer.isBuffer(masterSecret) ? masterSecret : Buffer.from(String(masterSecret), 'utf8');
    if (!Buffer.isBuffer(salt) || salt.length !== SALT_SIZE) {
        throw new Error(`Salt must be a Buffer of length ${SALT_SIZE}.`);
    }

    // Pseudo-Random Key (PRK) via HMAC-SHA512
    const prk = crypto.createHmac('sha512', salt).update(secretBuf).digest();

    // Derive 32B for AES-256-GCM
    const keyAes = Buffer.from(crypto.hkdfSync('sha512', prk, salt, Buffer.from('myco-dual-layer-aes-gcm', 'utf8'), 32));

    // Derive 32B for ChaCha20-Poly1305
    const keyChaCha = Buffer.from(crypto.hkdfSync('sha512', prk, salt, Buffer.from('myco-dual-layer-chacha20-poly1305', 'utf8'), 32));

    // Derive 32B for Auth verification
    const keyAuth = Buffer.from(crypto.hkdfSync('sha512', prk, salt, Buffer.from('myco-key-auth-check', 'utf8'), 32));

    // Generate 16B verification tag
    const checkTag = crypto.createHmac('sha256', keyAuth).update(VERIFY_STRING).digest().subarray(0, CHECK_TAG_SIZE);

    return { keyAes, keyChaCha, checkTag };
}

/**
 * Resolves master secret from options, environment, or key file
 * @param {string} [customSecret]
 * @param {string} [workingDir]
 * @returns {string}
 */
function resolveSecret(customSecret = null, workingDir = process.cwd()) {
    if (customSecret && customSecret.trim()) {
        return customSecret.trim();
    }

    if (process.env.MYCO_SECRET && process.env.MYCO_SECRET.trim()) {
        return process.env.MYCO_SECRET.trim();
    }

    // Try reading .myco-key file in workingDir
    const keyFilePath = path.join(workingDir, '.myco-key');
    if (fs.existsSync(keyFilePath)) {
        try {
            const fileSecret = fs.readFileSync(keyFilePath, 'utf8').trim();
            if (fileSecret) return fileSecret;
        } catch {}
    }

    // Try reading .env file if dotenv isn't active
    const envFilePath = path.join(workingDir, '.env');
    if (fs.existsSync(envFilePath)) {
        try {
            const envContent = fs.readFileSync(envFilePath, 'utf8');
            const match = envContent.match(/^\s*MYCO_SECRET\s*=\s*(["']?)(.*?)\1\s*$/m);
            if (match && match[2]) return match[2].trim();
        } catch {}
    }

    throw new Error(
        'Missing encryption key. Please provide --secret, set MYCO_SECRET in .env, or run "myco keygen".'
    );
}

/**
 * Creates container file header with salt and verification check tag
 * @param {string|Buffer} secret
 * @param {Buffer} [customSalt]
 * @returns {{ header: Buffer, keys: { keyAes: Buffer, keyChaCha: Buffer } }}
 */
function createContainerHeader(secret, customSalt = null) {
    const salt = customSalt || crypto.randomBytes(SALT_SIZE);
    const { keyAes, keyChaCha, checkTag } = deriveVaultKeys(secret, salt);

    // Header layout: [MAGIC (4B)] [VERSION (1B)] [SALT (16B)] [CHECK_TAG (16B)] = 37B
    const header = Buffer.concat([
        FILE_MAGIC,
        Buffer.from([0x01]),
        salt,
        checkTag
    ]);

    return {
        header,
        salt,
        keys: { keyAes, keyChaCha }
    };
}

/**
 * Reads and verifies container file header
 * @param {Buffer} headerBuffer
 * @param {string|Buffer} secret
 * @returns {{ salt: Buffer, keys: { keyAes: Buffer, keyChaCha: Buffer } }}
 */
function verifyAndDeriveHeader(headerBuffer, secret) {
    if (!Buffer.isBuffer(headerBuffer) || headerBuffer.length < 37) {
        throw new Error('Invalid container header: file is too small or corrupted.');
    }

    const magic = headerBuffer.subarray(0, 4);
    if (!magic.equals(FILE_MAGIC)) {
        throw new Error(`Invalid file magic: expected 'MYCO', got '${magic.toString('utf8', 0, 4)}'`);
    }

    const version = headerBuffer[4];
    if (version !== 1) {
        throw new Error(`Unsupported MYCO format version: ${version}`);
    }

    const salt = headerBuffer.subarray(5, 5 + SALT_SIZE);
    const expectedCheckTag = headerBuffer.subarray(5 + SALT_SIZE, 5 + SALT_SIZE + CHECK_TAG_SIZE);

    const { keyAes, keyChaCha, checkTag } = deriveVaultKeys(secret, salt);

    // Constant-time comparison
    if (!crypto.timingSafeEqual(expectedCheckTag, checkTag)) {
        const err = new Error('Decryption failed: Incorrect secret passphrase or corrupt container header.');
        err.code = 'ERR_INVALID_KEY';
        throw err;
    }

    return {
        salt,
        keys: { keyAes, keyChaCha }
    };
}

/**
 * Encrypts a payload buffer using Dual AEAD (AES-256-GCM + ChaCha20-Poly1305)
 * @param {Buffer} plaintext
 * @param {{ keyAes: Buffer, keyChaCha: Buffer }} keys
 * @returns {Buffer} Encrypted binary chunk: [aesIv (12B)] [chachaIv (12B)] [chachaTag (16B)] [ciphertext]
 */
function encryptDual(plaintext, keys) {
    if (!Buffer.isBuffer(plaintext)) {
        plaintext = Buffer.from(plaintext);
    }

    // 1. Layer 1 (Inner): AES-256-GCM
    const aesIv = crypto.randomBytes(12);
    const aesCipher = crypto.createCipheriv('aes-256-gcm', keys.keyAes, aesIv);
    const aesCiphertext = Buffer.concat([aesCipher.update(plaintext), aesCipher.final()]);
    const aesTag = aesCipher.getAuthTag(); // 16B

    // Pack aesTag + aesCiphertext for outer layer
    const innerPayload = Buffer.concat([aesTag, aesCiphertext]);

    // 2. Layer 2 (Outer): ChaCha20-Poly1305
    const chachaIv = crypto.randomBytes(12);
    const chachaCipher = crypto.createCipheriv('chacha20-poly1305', keys.keyChaCha, chachaIv, { authTagLength: 16 });
    const outerCiphertext = Buffer.concat([chachaCipher.update(innerPayload), chachaCipher.final()]);
    const chachaTag = chachaCipher.getAuthTag(); // 16B

    // Layout: [aesIv: 12B][chachaIv: 12B][chachaTag: 16B][outerCiphertext: ...]
    return Buffer.concat([
        aesIv,
        chachaIv,
        chachaTag,
        outerCiphertext
    ]);
}

/**
 * Decrypts a Dual AEAD encrypted chunk
 * @param {Buffer} encryptedChunk
 * @param {{ keyAes: Buffer, keyChaCha: Buffer }} keys
 * @returns {Buffer} Original plaintext
 */
function decryptDual(encryptedChunk, keys) {
    if (!Buffer.isBuffer(encryptedChunk) || encryptedChunk.length < 40) {
        throw new Error('Encrypted payload too short or malformed.');
    }

    const aesIv = encryptedChunk.subarray(0, 12);
    const chachaIv = encryptedChunk.subarray(12, 24);
    const chachaTag = encryptedChunk.subarray(24, 40);
    const outerCiphertext = encryptedChunk.subarray(40);

    // 1. Outer Layer: ChaCha20-Poly1305
    const chachaDecipher = crypto.createDecipheriv('chacha20-poly1305', keys.keyChaCha, chachaIv, { authTagLength: 16 });
    chachaDecipher.setAuthTag(chachaTag);
    const innerPayload = Buffer.concat([chachaDecipher.update(outerCiphertext), chachaDecipher.final()]);

    if (innerPayload.length < 16) {
        throw new Error('Corrupted inner payload in chunk.');
    }

    // 2. Inner Layer: AES-256-GCM
    const aesTag = innerPayload.subarray(0, 16);
    const aesCiphertext = innerPayload.subarray(16);

    const aesDecipher = crypto.createDecipheriv('aes-256-gcm', keys.keyAes, aesIv);
    aesDecipher.setAuthTag(aesTag);
    const plaintext = Buffer.concat([aesDecipher.update(aesCiphertext), aesDecipher.final()]);

    return plaintext;
}

/**
 * Generates a random secure key hex string
 * @returns {string} 64-char hex string (256-bit entropy)
 */
function generateRandomKey() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    deriveVaultKeys,
    resolveSecret,
    createContainerHeader,
    verifyAndDeriveHeader,
    encryptDual,
    decryptDual,
    generateRandomKey
};
