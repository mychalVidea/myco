const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const {
    VaultWriter,
    VaultReader,
    packFiles,
    unpackVault,
    queryVault,
    generateKey,
    crypto: mycoCrypto,
    compressor: mycoCompressor,
    tokenizer: mycoTokenizer,
    format: mycoFormat
} = require('../src/index');

test('Crypto: Derive keys and encrypt/decrypt Dual AEAD (AES-256-GCM + ChaCha20-Poly1305)', () => {
    const secret = 'super-secret-master-key-12345';
    const salt = Buffer.alloc(16, 0x42);
    const keys = mycoCrypto.deriveVaultKeys(secret, salt);

    assert.ok(Buffer.isBuffer(keys.keyAes) && keys.keyAes.length === 32);
    assert.ok(Buffer.isBuffer(keys.keyChaCha) && keys.keyChaCha.length === 32);
    assert.ok(Buffer.isBuffer(keys.checkTag) && keys.checkTag.length === 16);

    const plaintext = Buffer.from('Testing military-grade dual-layer encryption for log records!');
    const encrypted = mycoCrypto.encryptDual(plaintext, keys);

    assert.notDeepEqual(encrypted, plaintext);
    const decrypted = mycoCrypto.decryptDual(encrypted, keys);
    assert.equal(decrypted.toString('utf8'), plaintext.toString('utf8'));
});

test('Crypto: Header validation and wrong password detection', () => {
    const correctSecret = 'correct-passphrase-alpha';
    const wrongSecret = 'wrong-passphrase-bravo';

    const { header } = mycoCrypto.createContainerHeader(correctSecret);
    assert.equal(header.length, mycoFormat.HEADER_SIZE);

    // Verify with correct secret succeeds
    const verified = mycoCrypto.verifyAndDeriveHeader(header, correctSecret);
    assert.ok(verified.keys.keyAes);

    // Verify with wrong secret must throw ERR_INVALID_KEY
    assert.throws(() => {
        mycoCrypto.verifyAndDeriveHeader(header, wrongSecret);
    }, (err) => err.code === 'ERR_INVALID_KEY');
});

test('Compressor: Brotli compress & decompress roundtrip', () => {
    const rawData = Buffer.from('Log line repeat. '.repeat(100), 'utf8');
    const compressed = mycoCompressor.compress(rawData, { mode: 'balanced' });

    assert.ok(compressed.length < rawData.length);
    const decompressed = mycoCompressor.decompress(compressed);
    assert.equal(decompressed.toString('utf8'), rawData.toString('utf8'));
});

test('Tokenizer: COL4 Columnar binary encoding & decoding', () => {
    const records = [
        { timestamp: 1774300000000, source: 'minecraft', level: 'INFO', message: 'Player Steve logged in' },
        { timestamp: 1774300001000, source: 'minecraft', level: 'WARN', message: 'Can\'t keep up! Is the server overloaded?' },
        { timestamp: 1774300002500, source: 'nginx', level: 'ERROR', message: 'upstream timed out (110: Connection timed out)' }
    ];

    const encoded = mycoTokenizer.encodeChunk(records);
    assert.ok(Buffer.isBuffer(encoded) && encoded.length > 0);

    const decoded = mycoTokenizer.decodeChunk(encoded);
    assert.equal(decoded.length, records.length);

    for (let i = 0; i < records.length; i++) {
        assert.equal(decoded[i].timestamp, records[i].timestamp);
        assert.equal(decoded[i].source, records[i].source);
        assert.equal(decoded[i].level, records[i].level);
        assert.equal(decoded[i].message, records[i].message);
    }
});

test('VaultWriter & VaultReader: End-to-end container write and read with query filtering', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'myco-test-vault-'));
    const secret = 'e2e-vault-test-secret-key-999';

    try {
        const writer = new VaultWriter({
            vaultDir: tmpDir,
            secret,
            rotation: 'daily',
            flushIntervalMs: 50
        });

        // Write batch of log records
        writer.write({ timestamp: 1774300000000, source: 'app-service', level: 'INFO', message: 'Application initialized.' });
        writer.write({ timestamp: 1774300001000, source: 'database', level: 'WARN', message: 'Slow query detected on table users.' });
        writer.write({ timestamp: 1774300002000, source: 'auth-service', level: 'ERROR', message: 'Invalid credentials for user admin.' });
        writer.write({ timestamp: 1774300003000, source: 'app-service', level: 'INFO', message: 'Heartbeat OK.' });

        writer.close();

        // Check container file was created
        const containerPath = path.join(tmpDir, writer.activeFileName);
        assert.ok(fs.existsSync(containerPath));

        const reader = new VaultReader(containerPath, secret);

        // 1. Inspect container
        const metadata = await reader.inspect();
        assert.equal(metadata.totalRecords, 4);
        assert.ok(metadata.fileSize > 0);

        // 2. Read all records
        const allRecords = await reader.readAll();
        assert.equal(allRecords.length, 4);
        assert.equal(allRecords[0].message, 'Application initialized.');

        // 3. Filter by level
        const errorRecords = await reader.readAll({ levels: 'ERROR' });
        assert.equal(errorRecords.length, 1);
        assert.equal(errorRecords[0].source, 'auth-service');

        // 4. Filter by query
        const dbRecords = await reader.readAll({ query: 'Slow query' });
        assert.equal(dbRecords.length, 1);
        assert.equal(dbRecords[0].source, 'database');

        // 5. Query directory helper
        const dirResults = await queryVault(tmpDir, secret, { sources: 'app-service' });
        assert.equal(dirResults.length, 2);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Pack & Unpack: Convenience helpers packFiles and unpackVault', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'myco-pack-test-'));
    const logFilePath = path.join(tmpDir, 'sample.log');
    const outVaultPath = path.join(tmpDir, 'archive.myco');
    const restoredLogPath = path.join(tmpDir, 'restored.log');
    const secret = 'pack-unpack-secret-key';

    try {
        const rawLines = [
            '2026-09-22 10:00:00 [INFO] Worker started',
            '2026-09-22 10:00:05 [WARN] Queue capacity reaching 80%',
            '2026-09-22 10:00:10 [ERROR] Job #442 failed with TimeoutError'
        ];
        fs.writeFileSync(logFilePath, rawLines.join('\n'), 'utf8');

        // Pack
        const packStats = await packFiles(logFilePath, outVaultPath, secret, { source: 'sample-worker' });
        assert.ok(fs.existsSync(outVaultPath));
        assert.equal(packStats.recordsPacked, 3);
        assert.ok(packStats.storedBytes > 0);

        // Unpack
        const unpackResult = await unpackVault(outVaultPath, restoredLogPath, secret);
        assert.equal(unpackResult.extractedLines, 3);
        assert.ok(fs.existsSync(restoredLogPath));

        const restoredContent = fs.readFileSync(restoredLogPath, 'utf8');
        assert.ok(restoredContent.includes('Worker started'));
        assert.ok(restoredContent.includes('TimeoutError'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
