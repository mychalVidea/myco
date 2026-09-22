/**
 * MYCO Vault - Collector Daemon Orchestrator
 * Loads configuration, instantiates log sources, applies pipeline filters, and routes lines to VaultWriter.
 */

const path = require('path');
const { FileSource, PatternSource, UdpSyslogSource, resolvePath } = require('./sources');
const { VaultWriter } = require('../core/vault-writer');
const { detectLogLevel } = require('../core/tokenizer');

class Collector {
    /**
     * @param {Object} config
     * @param {string} config.vaultDir
     * @param {string} config.secret
     * @param {'daily'|'hourly'} [config.rotation='daily']
     * @param {number} [config.flushIntervalMs=5000]
     * @param {number} [config.maxBatchRecords=500]
     * @param {number} [config.maxBatchBytes=65536]
     * @param {'fast'|'balanced'|'max'} [config.compressMode='fast']
     * @param {Array<Object>} [config.sources=[]]
     * @param {Object} [config.filters={}]
     */
    constructor(config) {
        this.config = config;
        this.writer = new VaultWriter({
            vaultDir: config.vaultDir,
            secret: config.secret,
            rotation: config.rotation || 'daily',
            flushIntervalMs: config.flushIntervalMs || 5000,
            maxBatchRecords: config.maxBatchRecords || 500,
            maxBatchBytes: config.maxBatchBytes || 65536,
            compressMode: config.compressMode || 'fast'
        });

        this.activeSources = [];
        this.onRecordBroadcast = null; // Hook for SSE real-time web streaming

        // Initialize Filter Pipeline
        this.filterStripAnsi = Boolean(config.filters?.stripAnsi);
        this.filterCollapseDuplicates = Boolean(config.filters?.collapseDuplicates);
        this.ignorePatterns = [];

        if (Array.isArray(config.filters?.ignoreRegex)) {
            for (const pat of config.filters.ignoreRegex) {
                try {
                    this.ignorePatterns.push(pat instanceof RegExp ? pat : new RegExp(pat));
                } catch (e) {
                    console.warn(`[MYCO Collector] Invalid ignore regex "${pat}":`, e.message);
                }
            }
        }

        // State for duplicate collapsing: source -> { message, count, timer }
        this.lastMessages = new Map();
    }

    start() {
        console.log(`[MYCO Collector] Starting ingestion engine into ${this.config.vaultDir}...`);

        const sources = this.config.sources || [];
        for (const src of sources) {
            if (src.enabled === false) {
                continue;
            }

            const name = src.name || src.id || 'source';
            let instance = null;

            // Check if UDP / Syslog
            const isUdp = src.type === 'udp' || src.type === 'syslog' || src.preset === 'syslog' || Boolean(src.port);

            if (isUdp) {
                instance = new UdpSyslogSource({
                    name,
                    port: src.port || 5140,
                    host: src.host || '127.0.0.1'
                }, (rec) => this.ingest(rec));
            } else if (src.path) {
                const resolved = resolvePath(src.path);
                const hasWildcard = resolved.includes('*') || resolved.includes('?');

                if (hasWildcard) {
                    const dir = path.dirname(resolved);
                    const pattern = path.basename(resolved);
                    instance = new PatternSource({
                        name,
                        dir,
                        pattern
                    }, (rec) => this.ingest(rec));
                } else if (src.pattern) {
                    // Pattern in directory
                    instance = new PatternSource({
                        name,
                        dir: resolved,
                        pattern: src.pattern
                    }, (rec) => this.ingest(rec));
                } else {
                    instance = new FileSource({
                        name,
                        path: resolved,
                        tail: src.tail !== false
                    }, (rec) => this.ingest(rec));
                }
            } else {
                console.warn(`[MYCO Collector] Unknown or invalid source configuration:`, src);
                continue;
            }

            instance.start();
            this.activeSources.push(instance);
            console.log(`[MYCO Collector] Source registered: [${isUdp ? 'UDP' : 'FILE'}] ${name}`);
        }
    }

    /**
     * Ingests a raw record through filters and passes to VaultWriter & broadcast
     * @param {Object} rawRecord { timestamp, source, message, level }
     */
    ingest(rawRecord) {
        if (!rawRecord || !rawRecord.message) return;

        let msg = String(rawRecord.message);

        // 1. Strip ANSI escape sequences if configured
        if (this.filterStripAnsi) {
            msg = msg.replace(/\u001b\[[0-9;]*[a-zA-Z]/g, '');
        }

        // 2. Ignore Regex filter
        for (const regex of this.ignorePatterns) {
            if (regex.test(msg)) {
                return; // Dropped by filter
            }
        }

        const source = rawRecord.source || 'default';
        const level = rawRecord.level || detectLogLevel(msg);

        // 3. Duplicate collapsing
        if (this.filterCollapseDuplicates) {
            const last = this.lastMessages.get(source);
            const now = Date.now();

            if (last && last.message === msg && (now - last.time < 3000)) {
                last.count++;
                last.time = now;
                return; // Suppress duplicate
            }

            if (last && last.count > 1) {
                // Flush repeated count message
                const repeatedRec = {
                    timestamp: last.time,
                    source,
                    level: 'INFO',
                    message: `[Repeated ${last.count} times]`
                };
                this._dispatch(repeatedRec);
            }

            this.lastMessages.set(source, { message: msg, count: 1, time: now });
        }

        const rec = {
            timestamp: rawRecord.timestamp || Date.now(),
            source,
            level,
            message: msg
        };

        this._dispatch(rec);
    }

    _dispatch(record) {
        this.writer.write(record);
        if (typeof this.onRecordBroadcast === 'function') {
            try {
                this.onRecordBroadcast(record);
            } catch {}
        }
    }

    stop() {
        console.log('[MYCO Collector] Stopping all log sources...');
        for (const src of this.activeSources) {
            src.stop();
        }
        this.activeSources = [];

        // Flush any pending collapsed duplicates
        if (this.filterCollapseDuplicates) {
            for (const [source, last] of this.lastMessages.entries()) {
                if (last.count > 1) {
                    this.writer.write({
                        timestamp: last.time,
                        source,
                        level: 'INFO',
                        message: `[Repeated ${last.count} times]`
                    });
                }
            }
            this.lastMessages.clear();
        }

        this.writer.close();
        console.log('[MYCO Collector] Stopped gracefully. All logs flushed to vault containers.');
    }
}

module.exports = {
    Collector
};
