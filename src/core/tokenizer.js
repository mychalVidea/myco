/**
 * MYCO Vault - Columnar Log Tokenizer (COL4 Standard)
 * Zero-dependency: Uses pure Buffer operations and Varint (LEB128).
 * 
 * Features:
 * - Dynamic Source Dictionary (per-chunk dictionary, zero hardcoded source names)
 * - Sub-byte Bit Packing (5-bit source ID + 3-bit level packed in 1 byte)
 * - Inter-arrival Delta encoding (Δt_i = t_i - t_{i-1})
 * - Columnar Byte Shuffle (sections for metadata, deltas, lengths, text)
 */

const CHUNK_COL4_MAGIC = Buffer.from('COL4', 'utf8');

const LEVELS = {
    'TRACE': 0,
    'DEBUG': 1,
    'INFO': 2,
    'WARN': 3,
    'ERROR': 4,
    'FATAL': 5,
    'UNKNOWN': 6
};

const LEVEL_NAMES = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN'];

/**
 * Write Varint (LEB128) into buffer
 * @param {Buffer} buf
 * @param {number} val
 * @param {number} offset
 * @returns {number} Next offset
 */
function writeVarint(buf, val, offset) {
    let cursor = offset;
    let v = Math.max(0, Math.floor(val));
    while (v >= 0x80) {
        buf[cursor++] = (v & 0x7f) | 0x80;
        v >>>= 7;
    }
    buf[cursor++] = v & 0x7f;
    return cursor;
}

/**
 * Read Varint (LEB128) from buffer
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {{ value: number, nextOffset: number }}
 */
function readVarint(buf, offset) {
    let res = 0;
    let shift = 0;
    let cursor = offset;
    while (cursor < buf.length) {
        const byte = buf[cursor++];
        res |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }
    return { value: res, nextOffset: cursor };
}

/**
 * Calculate length in bytes for a number in Varint format
 * @param {number} val
 * @returns {number}
 */
function varintLength(val) {
    let len = 0;
    let v = Math.max(0, Math.floor(val));
    do {
        len++;
        v >>>= 7;
    } while (v > 0);
    return len;
}

/**
 * Heuristic log level detector from text
 * @param {string} text
 * @returns {number} Log level integer
 */
function detectLogLevel(text) {
    if (!text || typeof text !== 'string') return LEVELS.INFO;
    const lower = text.toLowerCase();
    if (lower.includes('fatal') || lower.includes('crash') || lower.includes('uncaughtexception') || lower.includes('panic')) return LEVELS.FATAL;
    if (lower.includes('error') || lower.includes('err ') || lower.includes('exception') || lower.includes('fail')) return LEVELS.ERROR;
    if (lower.includes('warn') || lower.includes('warning')) return LEVELS.WARN;
    if (lower.includes('debug')) return LEVELS.DEBUG;
    if (lower.includes('trace')) return LEVELS.TRACE;
    return LEVELS.INFO;
}

/**
 * Ochrana citlivých údajů: automatické zamaskování hesel v příkazech /login, /register, atd.
 * @param {string} text
 * @returns {string}
 */
function sanitizeLogMessage(text) {
    if (!text || typeof text !== 'string') return text || '';
    if (text.charCodeAt(0) === 0x2f || text.includes('login') || text.includes('register') || text.includes('changepassword')) {
        return text
            .replace(/(\/(?:login|register|reg|l|changepassword)\s+)([^\s]+)/gi, '$1***')
            .replace(/(issued server command:\s*\/(?:login|register|reg|l|changepassword)\s+)([^\s]+)/gi, '$1***');
    }
    return text;
}

/**
 * Encodes array of log records into COL4 Columnar binary Buffer
 * @param {Array<{ timestamp: number, source: string, level?: string|number, message: string }>} records
 * @returns {Buffer}
 */
function encodeChunk(records) {
    if (!records || records.length === 0) {
        return Buffer.alloc(0);
    }

    const count = records.length;

    // 1. Build dynamic source dictionary
    const sourceDict = [];
    const sourceMap = new Map();
    for (const rec of records) {
        const src = (rec.source || 'default').trim();
        if (!sourceMap.has(src)) {
            const idx = sourceDict.length;
            sourceDict.push(src);
            sourceMap.set(src, idx);
        }
    }

    // 2. Base timestamp
    const baseTs = records[0].timestamp || Date.now();

    // 3. Prepare columnar buffers
    // Column 1: Metadata (1 byte per record: 5 bits source, 3 bits level)
    const metaCol = Buffer.alloc(count);
    // Overflow list for source indices >= 31 (extremely rare)
    const overflowSources = [];

    // Column 2: Inter-arrival deltas
    let deltasLen = 0;
    const deltas = new Int32Array(count);
    let prevTs = baseTs;
    for (let i = 0; i < count; i++) {
        const curTs = records[i].timestamp || prevTs;
        const delta = Math.max(0, curTs - prevTs);
        deltas[i] = delta;
        deltasLen += varintLength(delta);
        prevTs = curTs;
    }
    const deltaCol = Buffer.alloc(deltasLen);
    let deltaCursor = 0;
    for (let i = 0; i < count; i++) {
        deltaCursor = writeVarint(deltaCol, deltas[i], deltaCursor);
    }

    // Column 3 & 4: Message lengths and continuous UTF-8 payload
    let textByteLen = 0;
    const msgBuffers = new Array(count);
    let lensColSize = 0;

    for (let i = 0; i < count; i++) {
        const rec = records[i];
        const srcIdx = sourceMap.get((rec.source || 'default').trim()) || 0;
        let lvl = LEVELS.INFO;
        if (typeof rec.level === 'number' && rec.level >= 0 && rec.level <= 6) {
            lvl = rec.level;
        } else if (typeof rec.level === 'string' && LEVELS[rec.level.toUpperCase()] !== undefined) {
            lvl = LEVELS[rec.level.toUpperCase()];
        } else {
            lvl = detectLogLevel(rec.message);
        }

        const packedSrc = srcIdx < 31 ? srcIdx : 31;
        metaCol[i] = (packedSrc & 0x1f) | ((lvl & 0x07) << 5);
        if (srcIdx >= 31) {
            overflowSources.push({ index: i, sourceId: srcIdx });
        }

        const cleanMsg = sanitizeLogMessage(rec.message);
        const msgBuf = Buffer.from(cleanMsg, 'utf8');
        msgBuffers[i] = msgBuf;
        textByteLen += msgBuf.length;
        lensColSize += varintLength(msgBuf.length);
    }

    const lensCol = Buffer.alloc(lensColSize);
    let lensCursor = 0;
    for (let i = 0; i < count; i++) {
        lensCursor = writeVarint(lensCol, msgBuffers[i].length, lensCursor);
    }

    const textCol = Buffer.concat(msgBuffers, textByteLen);

    // 4. Encode Source Dictionary
    let dictBytesLen = varintLength(sourceDict.length);
    const dictBufs = [];
    for (const src of sourceDict) {
        const sBuf = Buffer.from(src, 'utf8');
        dictBytesLen += varintLength(sBuf.length) + sBuf.length;
        dictBufs.push(sBuf);
    }
    const dictCol = Buffer.alloc(dictBytesLen);
    let dictCursor = writeVarint(dictCol, sourceDict.length, 0);
    for (const sBuf of dictBufs) {
        dictCursor = writeVarint(dictCol, sBuf.length, dictCursor);
        sBuf.copy(dictCol, dictCursor);
        dictCursor += sBuf.length;
    }

    // 5. Overflow sources if any
    let overflowLen = varintLength(overflowSources.length);
    for (const item of overflowSources) {
        overflowLen += varintLength(item.index) + varintLength(item.sourceId);
    }
    const overflowCol = Buffer.alloc(overflowLen);
    let overCursor = writeVarint(overflowCol, overflowSources.length, 0);
    for (const item of overflowSources) {
        overCursor = writeVarint(overflowCol, item.index, overCursor);
        overCursor = writeVarint(overflowCol, item.sourceId, overCursor);
    }

    // 6. Header assembly:
    // [MAGIC: 4B]
    // [RECORD_COUNT: varint]
    // [BASE_TIMESTAMP: 8B BigInt BE]
    // [DICT_LEN: varint] [DICT_COL]
    // [OVERFLOW_LEN: varint] [OVERFLOW_COL]
    // [DELTA_LEN: varint] [DELTA_COL]
    // [LENS_LEN: varint] [LENS_COL]
    // [META_COL: count bytes]
    // [TEXT_COL: textByteLen bytes]
    const headerPrefixLen = 4 + varintLength(count) + 8 +
        varintLength(dictCol.length) +
        varintLength(overflowCol.length) +
        varintLength(deltaCol.length) +
        varintLength(lensCol.length);

    const prefixBuf = Buffer.alloc(headerPrefixLen);
    CHUNK_COL4_MAGIC.copy(prefixBuf, 0);
    let pCursor = 4;
    pCursor = writeVarint(prefixBuf, count, pCursor);
    prefixBuf.writeBigInt64BE(BigInt(baseTs), pCursor);
    pCursor += 8;
    pCursor = writeVarint(prefixBuf, dictCol.length, pCursor);
    pCursor = writeVarint(prefixBuf, overflowCol.length, pCursor);
    pCursor = writeVarint(prefixBuf, deltaCol.length, pCursor);
    pCursor = writeVarint(prefixBuf, lensCol.length, pCursor);

    return Buffer.concat([
        prefixBuf.subarray(0, pCursor),
        dictCol,
        overflowCol,
        metaCol,
        deltaCol,
        lensCol,
        textCol
    ]);
}

/**
 * Decodes COL4 Columnar binary Buffer into log records
 * @param {Buffer} buffer
 * @returns {Array<{ timestamp: number, source: string, level: string, message: string }>}
 */
function decodeChunk(buffer) {
    if (!buffer || buffer.length < 13) {
        return [];
    }

    const magic = buffer.subarray(0, 4);
    if (!magic.equals(CHUNK_COL4_MAGIC)) {
        throw new Error(`Unsupported chunk format magic: ${magic.toString('utf8')}`);
    }

    let cursor = 4;
    const countVar = readVarint(buffer, cursor);
    const count = countVar.value;
    cursor = countVar.nextOffset;

    if (count === 0) return [];

    const baseTs = Number(buffer.readBigInt64BE(cursor));
    cursor += 8;

    const dictLenVar = readVarint(buffer, cursor);
    const dictLen = dictLenVar.value;
    cursor = dictLenVar.nextOffset;

    const overLenVar = readVarint(buffer, cursor);
    const overLen = overLenVar.value;
    cursor = overLenVar.nextOffset;

    const deltaLenVar = readVarint(buffer, cursor);
    const deltaLen = deltaLenVar.value;
    cursor = deltaLenVar.nextOffset;

    const lensLenVar = readVarint(buffer, cursor);
    const lensLen = lensLenVar.value;
    cursor = lensLenVar.nextOffset;

    // Read Source Dictionary
    let dictCursor = cursor;
    const numDictEntriesVar = readVarint(buffer, dictCursor);
    const numDictEntries = numDictEntriesVar.value;
    dictCursor = numDictEntriesVar.nextOffset;

    const sourceDict = new Array(numDictEntries);
    for (let i = 0; i < numDictEntries; i++) {
        const sLenVar = readVarint(buffer, dictCursor);
        dictCursor = sLenVar.nextOffset;
        sourceDict[i] = buffer.toString('utf8', dictCursor, dictCursor + sLenVar.value);
        dictCursor += sLenVar.value;
    }
    cursor += dictLen;

    // Read Overflows
    let overCursor = cursor;
    const numOverflowsVar = readVarint(buffer, overCursor);
    const numOverflows = numOverflowsVar.value;
    overCursor = numOverflowsVar.nextOffset;
    const overflowMap = new Map();
    for (let i = 0; i < numOverflows; i++) {
        const idxVar = readVarint(buffer, overCursor);
        overCursor = idxVar.nextOffset;
        const srcIdVar = readVarint(buffer, overCursor);
        overCursor = srcIdVar.nextOffset;
        overflowMap.set(idxVar.value, srcIdVar.value);
    }
    cursor += overLen;

    // Read Meta Column (count bytes)
    const metaCol = buffer.subarray(cursor, cursor + count);
    cursor += count;

    // Read Delta Column
    const deltaEnd = cursor + deltaLen;
    const timestamps = new Array(count);
    let curTs = baseTs;
    let dCursor = cursor;
    for (let i = 0; i < count; i++) {
        const dVar = readVarint(buffer, dCursor);
        dCursor = dVar.nextOffset;
        curTs += dVar.value;
        timestamps[i] = curTs;
    }
    cursor = deltaEnd;

    // Read Lens Column
    const lensEnd = cursor + lensLen;
    const lengths = new Array(count);
    let lCursor = cursor;
    for (let i = 0; i < count; i++) {
        const lVar = readVarint(buffer, lCursor);
        lCursor = lVar.nextOffset;
        lengths[i] = lVar.value;
    }
    cursor = lensEnd;

    // Read Continuous Text Column
    const records = new Array(count);
    let textCursor = cursor;
    for (let i = 0; i < count; i++) {
        const byte = metaCol[i];
        let srcIdx = byte & 0x1f;
        const lvlIdx = (byte >>> 5) & 0x07;

        if (srcIdx === 31 && overflowMap.has(i)) {
            srcIdx = overflowMap.get(i);
        }

        const source = sourceDict[srcIdx] || 'default';
        const level = LEVEL_NAMES[lvlIdx] || 'INFO';
        const len = lengths[i];
        const message = buffer.toString('utf8', textCursor, textCursor + len);
        textCursor += len;

        records[i] = {
            timestamp: timestamps[i],
            source,
            level,
            message
        };
    }

    return records;
}

module.exports = {
    encodeChunk,
    decodeChunk,
    detectLogLevel,
    LEVELS,
    LEVEL_NAMES,
    writeVarint,
    readVarint,
    varintLength
};
