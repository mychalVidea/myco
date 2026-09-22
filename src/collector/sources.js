/**
 * MYCO Vault - Log Sources Implementation
 * Zero-dependency: Native fs streams, dgram for UDP syslog, readline, os homedir.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const dgram = require('dgram');
const readline = require('readline');

/**
 * Resolves path expanding ~ to user's home directory
 * @param {string} rawPath
 * @returns {string}
 */
function resolvePath(rawPath) {
    if (!rawPath) return '';
    if (rawPath === '~' || rawPath.startsWith('~/')) {
        return path.resolve(os.homedir(), rawPath.slice(rawPath === '~' ? 1 : 2));
    }
    return path.resolve(rawPath);
}

/**
 * Converts a simple glob pattern (e.g. *.log, access-*.log) to RegExp
 * @param {string} pattern
 * @returns {RegExp}
 */
function globToRegex(pattern) {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp(`^${escaped}$`, 'i');
}

class FileSource {
    /**
     * @param {Object} config
     * @param {string} config.name
     * @param {string} config.path
     * @param {boolean} [config.tail=true]
     * @param {Function} onRecord Callback (record) => void
     */
    constructor(config, onRecord) {
        this.name = config.name || 'file';
        this.filePath = resolvePath(config.path);
        this.tail = config.tail !== false;
        this.onRecord = onRecord;
        this.currentSize = 0;
        this.watchHandle = null;
        this.pollInterval = null;
        this.closed = false;
    }

    start() {
        if (!fs.existsSync(this.filePath)) {
            // Wait for file creation
            const dir = path.dirname(this.filePath);
            if (fs.existsSync(dir)) {
                this.pollInterval = setInterval(() => {
                    if (fs.existsSync(this.filePath)) {
                        clearInterval(this.pollInterval);
                        this.start();
                    }
                }, 2000);
                if (this.pollInterval.unref) this.pollInterval.unref();
            }
            return;
        }

        try {
            const stat = fs.statSync(this.filePath);
            if (this.tail) {
                this.currentSize = stat.size;
            } else {
                this.currentSize = 0;
                this._readDelta();
            }

            this.watchHandle = fs.watch(this.filePath, (eventType) => {
                if (eventType === 'change' || eventType === 'rename') {
                    this._readDelta();
                }
            });

            // Backup polling every 1000ms
            this.pollInterval = setInterval(() => {
                this._readDelta();
            }, 1000);
            if (this.pollInterval.unref) this.pollInterval.unref();
        } catch (err) {
            console.warn(`[MYCO FileSource ${this.name}] Unable to inspect file ${this.filePath}: ${err.message}`);
        }
    }

    _readDelta() {
        if (this.closed || !fs.existsSync(this.filePath)) return;

        try {
            const stat = fs.statSync(this.filePath);
            if (stat.size < this.currentSize) {
                // File was truncated or rotated
                this.currentSize = 0;
            }

            if (stat.size === this.currentSize) return;

            const readStream = fs.createReadStream(this.filePath, {
                start: this.currentSize,
                end: stat.size,
                encoding: 'utf8'
            });

            this.currentSize = stat.size;

            const rl = readline.createInterface({
                input: readStream,
                crlfDelay: Infinity
            });

            rl.on('line', (line) => {
                const trimmed = line.trim();
                if (trimmed.length > 0) {
                    this.onRecord({
                        timestamp: Date.now(),
                        source: this.name,
                        message: trimmed
                    });
                }
            });
        } catch (err) {
            // File might be temporarily locked during log rotation
        }
    }

    stop() {
        this.closed = true;
        if (this.watchHandle) {
            try { this.watchHandle.close(); } catch {}
            this.watchHandle = null;
        }
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }
}

class PatternSource {
    /**
     * Watches a directory for multiple files matching glob pattern or directory
     * @param {Object} config
     * @param {string} config.name
     * @param {string} config.dir Directory path
     * @param {string} config.pattern e.g. *.log
     * @param {Function} onRecord
     */
    constructor(config, onRecord) {
        this.name = config.name || 'glob';
        this.dir = resolvePath(config.dir);
        this.pattern = config.pattern || '*.log';
        this.regex = globToRegex(this.pattern);
        this.onRecord = onRecord;
        this.tracked = new Map(); // filepath -> FileSource
        this.dirWatcher = null;
        this.scanInterval = null;
        this.closed = false;
    }

    start() {
        this._scan();

        if (fs.existsSync(this.dir)) {
            try {
                this.dirWatcher = fs.watch(this.dir, () => {
                    this._scan();
                });
            } catch {}
        }

        this.scanInterval = setInterval(() => {
            this._scan();
        }, 5000);
        if (this.scanInterval.unref) this.scanInterval.unref();
    }

    _scan() {
        if (this.closed || !fs.existsSync(this.dir)) return;

        try {
            const files = fs.readdirSync(this.dir);
            for (const file of files) {
                if (this.regex.test(file)) {
                    const full = path.join(this.dir, file);
                    if (!this.tracked.has(full)) {
                        const fileSrc = new FileSource({
                            name: `${this.name}/${file}`,
                            path: full,
                            tail: true
                        }, this.onRecord);
                        fileSrc.start();
                        this.tracked.set(full, fileSrc);
                    }
                }
            }
        } catch {}
    }

    stop() {
        this.closed = true;
        if (this.dirWatcher) {
            try { this.dirWatcher.close(); } catch {}
            this.dirWatcher = null;
        }
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
            this.scanInterval = null;
        }
        for (const src of this.tracked.values()) {
            src.stop();
        }
        this.tracked.clear();
    }
}

class UdpSyslogSource {
    /**
     * @param {Object} config
     * @param {string} config.name
     * @param {number} [config.port=5140]
     * @param {string} [config.host='127.0.0.1']
     * @param {Function} onRecord
     */
    constructor(config, onRecord) {
        this.name = config.name || 'syslog';
        this.port = config.port || 5140;
        this.host = config.host || '127.0.0.1';
        this.onRecord = onRecord;
        this.server = null;
    }

    start() {
        this.server = dgram.createSocket('udp4');

        this.server.on('message', (msg) => {
            const text = msg.toString('utf8').trim();
            if (text) {
                this.onRecord({
                    timestamp: Date.now(),
                    source: this.name,
                    message: text
                });
            }
        });

        this.server.on('error', (err) => {
            console.error(`[MYCO UDP Source ${this.name}] Error:`, err.message);
        });

        this.server.bind(this.port, this.host, () => {
            console.log(`[MYCO Collector] UDP syslog listener active on ${this.host}:${this.port} (${this.name})`);
        });
    }

    stop() {
        if (this.server) {
            try {
                this.server.close();
            } catch {}
            this.server = null;
        }
    }
}

module.exports = {
    FileSource,
    PatternSource,
    UdpSyslogSource,
    resolvePath
};
