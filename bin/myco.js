#!/usr/bin/env node

/**
 * MYCO Vault - Zero-Dependency Encrypted Log Container & Manager CLI
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const {
    VaultWriter,
    VaultReader,
    Collector,
    ViewerServer,
    packFiles,
    unpackVault,
    queryVault,
    generateKey,
    crypto: mycoCrypto,
    format: mycoFormat
} = require('../src/index');

const pkg = require('../package.json');

// ANSI Colors
const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    blue: '\x1b[38;2;10;103;229m',
    cyan: '\x1b[36m',
    green: '\x1b[38;2;33;222;0m',
    red: '\x1b[38;2;245;21;21m',
    yellow: '\x1b[33m',
    magenta: '\x1b[35m',
    gray: '\x1b[90m'
};

function printBanner() {
    console.log(`${colors.blue}${colors.bold}MYCO Vault${colors.reset} ${colors.gray}v${pkg.version}${colors.reset} - ${colors.dim}Encrypted Brotli Log Container${colors.reset}`);
}

function printHelp() {
    printBanner();
    console.log(`
${colors.bold}USAGE:${colors.reset}
  myco <command> [options]

${colors.bold}COMMANDS:${colors.reset}
  ${colors.blue}daemon${colors.reset}    Start log collection daemon & embedded web UI
  ${colors.blue}ui${colors.reset}        Launch standalone embedded web viewer
  ${colors.blue}pack${colors.reset}      Encrypt and compress raw logs into a .myco container
  ${colors.blue}unpack${colors.reset}    Decrypt and extract .myco container back to plain text
  ${colors.blue}query${colors.reset}     Search decrypted records across vault containers
  ${colors.blue}tail${colors.reset}      Live tail or inspect latest log records
  ${colors.blue}keygen${colors.reset}    Generate a cryptographically secure 256-bit encryption key
  ${colors.blue}help${colors.reset}      Show help and usage guide

${colors.bold}GLOBAL OPTIONS:${colors.reset}
  -c, --config <file>     Path to configuration JSON (default: myco.config.json)
  -s, --secret <key>      Master encryption key (or set VAULT_SECRET env)
  -v, --vault <dir>       Path to vault directory (default: ./vault)
  -h, --help              Show help information
  --version               Show version number

${colors.bold}EXAMPLES:${colors.reset}
  ${colors.dim}# Generate a new 256-bit secret key${colors.reset}
  myco keygen

  ${colors.dim}# Start the collector daemon with default config${colors.reset}
  myco daemon

  ${colors.dim}# Start web UI on port 8080${colors.reset}
  myco ui --port 8080 --vault ./vault

  ${colors.dim}# Encrypt a single log file${colors.reset}
  myco pack ./server.log --out ./vault --secret "my-secret-key"

  ${colors.dim}# Decrypt container to plain text${colors.reset}
  myco unpack ./vault/vault-2026-09-22.myco --out ./restored.log

  ${colors.dim}# Search for errors across all vault archives${colors.reset}
  myco query ./vault --level ERROR --query "database connection"
`);
}

/**
 * Simple argument parser for CLI
 */
function parseArgs(args) {
    const parsed = {
        command: args[0] || 'help',
        flags: {},
        positionals: []
    };

    for (let i = 1; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            const eqIdx = arg.indexOf('=');
            if (eqIdx !== -1) {
                const key = arg.slice(2, eqIdx);
                const val = arg.slice(eqIdx + 1);
                parsed.flags[key] = val;
            } else {
                const key = arg.slice(2);
                const next = args[i + 1];
                if (next && !next.startsWith('-')) {
                    parsed.flags[key] = next;
                    i++;
                } else {
                    parsed.flags[key] = true;
                }
            }
        } else if (arg.startsWith('-')) {
            const key = arg.slice(1);
            const next = args[i + 1];
            if (next && !next.startsWith('-')) {
                parsed.flags[key] = next;
                i++;
            } else {
                parsed.flags[key] = true;
            }
        } else {
            parsed.positionals.push(arg);
        }
    }

    return parsed;
}

/**
 * Load configuration from file, env or defaults
 */
function loadConfig(explicitFile = null) {
    const candidates = [];
    if (explicitFile) candidates.push(path.resolve(explicitFile));
    if (process.env.MYCO_CONFIG) candidates.push(path.resolve(process.env.MYCO_CONFIG));
    candidates.push(path.resolve('myco.config.json'));
    candidates.push(path.resolve('myco.config.example.json'));
    candidates.push(path.resolve('config.json'));

    let loaded = null;
    let configPath = null;
    for (const cand of candidates) {
        if (fs.existsSync(cand)) {
            try {
                loaded = JSON.parse(fs.readFileSync(cand, 'utf8'));
                configPath = cand;
                break;
            } catch (e) {
                console.warn(`${colors.yellow}Warning: Failed to parse ${cand}: ${e.message}${colors.reset}`);
            }
        }
    }

    const config = loaded || {};

    // Environment and flag overrides
    config.vaultSecret = config.vaultSecret || config.secret || process.env.VAULT_SECRET || process.env.MYCO_SECRET || null;
    config.vaultDir = config.vaultDir || process.env.VAULT_DIR || './vault';
    config.rotation = config.rotation || 'daily';
    config.configPath = configPath;

    return config;
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        printHelp();
        process.exit(0);
    }

    if (args.includes('--version') || args.includes('-v') && args.length === 1) {
        console.log(`v${pkg.version}`);
        process.exit(0);
    }

    const { command, flags, positionals } = parseArgs(args);
    const configPath = flags.config || flags.c || null;
    const config = loadConfig(configPath);

    // Override config with CLI flags
    const secret = flags.secret || flags.s || config.vaultSecret;
    const vaultDir = flags.vault || flags.v || positionals[0] || config.vaultDir || './vault';

    switch (command.toLowerCase()) {
        case 'keygen': {
            const key = generateKey();
            console.log(`\n${colors.green}Generated High-Entropy 256-bit Encryption Key:${colors.reset}`);
            console.log(`\n  ${colors.bold}${key}${colors.reset}\n`);
            console.log(`${colors.gray}Add this to your .env or myco.config.json:${colors.reset}`);
            console.log(`  VAULT_SECRET="${key}"\n`);
            break;
        }

        case 'daemon': {
            printBanner();
            if (!secret) {
                console.error(`\n${colors.red}Error: Master secret key is required to start collector daemon.${colors.reset}`);
                console.error(`Set ${colors.bold}VAULT_SECRET${colors.reset} in .env or provide ${colors.bold}--secret <key>${colors.reset}.\n`);
                process.exit(1);
            }

            console.log(`${colors.blue}Initializing MYCO Collector Daemon...${colors.reset}`);
            console.log(`${colors.gray}Vault Directory: ${path.resolve(vaultDir)}${colors.reset}`);
            if (config.configPath) {
                console.log(`${colors.gray}Config Source:   ${config.configPath}${colors.reset}`);
            }

            const collector = new Collector({
                vaultDir,
                secret,
                rotation: config.rotation || 'daily',
                flushIntervalMs: config.flush?.intervalMs || config.flushIntervalMs || 5000,
                maxBatchRecords: config.flush?.maxRecords || 500,
                maxBatchBytes: config.flush?.maxBytes || 65536,
                compressMode: config.compression?.liveQuality ? (config.compression.liveQuality >= 9 ? 'max' : 'fast') : 'fast',
                sources: config.sources || [],
                filters: config.filters || {}
            });

            // Start Collector
            collector.start();

            // Optional Web UI
            let uiServer = null;
            if (config.ui?.enabled !== false && (flags.ui || config.ui)) {
                const uiPort = Number(flags.port || config.ui?.port || 8080);
                const uiHost = flags.host || config.ui?.host || '127.0.0.1';
                uiServer = new ViewerServer({
                    port: uiPort,
                    host: uiHost,
                    vaultDir,
                    defaultSecret: secret
                });

                // Pipe collector live logs to web viewer SSE stream
                collector.onRecordBroadcast = (record) => {
                    uiServer.broadcastRecord(record);
                };

                await uiServer.start();
                console.log(`${colors.green}Web Viewer UI: http://${uiHost}:${uiPort}${colors.reset}`);
            }

            console.log(`\n${colors.green}MYCO Daemon running. Press Ctrl+C to stop safely.${colors.reset}\n`);

            const shutdown = () => {
                console.log(`\n${colors.yellow}Shutting down MYCO Vault...${colors.reset}`);
                collector.stop();
                if (uiServer) uiServer.stop();
                process.exit(0);
            };

            process.on('SIGINT', shutdown);
            process.on('SIGTERM', shutdown);
            break;
        }

        case 'ui': {
            printBanner();
            const uiPort = Number(flags.port || config.ui?.port || 8080);
            const uiHost = flags.host || config.ui?.host || '127.0.0.1';
            const server = new ViewerServer({
                port: uiPort,
                host: uiHost,
                vaultDir,
                defaultSecret: secret || ''
            });

            await server.start();
            console.log(`${colors.green}Web Viewer active at:${colors.reset} ${colors.bold}http://${uiHost}:${uiPort}${colors.reset}`);
            console.log(`${colors.gray}Target vault: ${path.resolve(vaultDir)}${colors.reset}\n`);

            process.on('SIGINT', () => {
                console.log(`\nStopping Web Viewer...`);
                server.stop();
                process.exit(0);
            });
            break;
        }

        case 'pack': {
            const input = positionals[0];
            if (!input) {
                console.error(`${colors.red}Error: Please specify input file or directory to pack.${colors.reset}`);
                console.log(`Usage: myco pack <file.log|dir> [--out <vaultDir>] [--secret <key>]`);
                process.exit(1);
            }

            if (!secret) {
                console.error(`${colors.red}Error: Secret key is required to encrypt container.${colors.reset}`);
                process.exit(1);
            }

            const outPath = flags.out || flags.o || vaultDir;
            const sourceName = flags.source || path.basename(input, path.extname(input));

            console.log(`${colors.blue}Packing and encrypting:${colors.reset} ${input} -> ${outPath}`);
            const result = await packFiles(input, outPath, secret, { source: sourceName });

            console.log(`\n${colors.green}Pack completed successfully!${colors.reset}`);
            console.log(`  Target Container: ${result.vaultPath}`);
            console.log(`  Records Packed:   ${result.recordsPacked.toLocaleString()}`);
            console.log(`  Raw Text Size:    ${(result.rawBytes / 1024).toFixed(1)} KB`);
            console.log(`  Encrypted Size:   ${(result.storedBytes / 1024).toFixed(1)} KB`);
            if (result.rawBytes > 0) {
                const ratio = ((1 - (result.storedBytes / result.rawBytes)) * 100).toFixed(1);
                console.log(`  Compression:      ${ratio}% space saved`);
            }
            break;
        }

        case 'unpack': {
            const targetVault = positionals[0];
            if (!targetVault) {
                console.error(`${colors.red}Error: Please specify .myco container to unpack.${colors.reset}`);
                console.log(`Usage: myco unpack <container.myco> [--out <file.log>] [--secret <key>]`);
                process.exit(1);
            }

            if (!secret) {
                console.error(`${colors.red}Error: Secret key is required to decrypt container.${colors.reset}`);
                process.exit(1);
            }

            const outDest = flags.out || flags.o || null;
            console.log(`${colors.blue}Decrypting container:${colors.reset} ${targetVault}`);
            const result = await unpackVault(targetVault, outDest, secret);

            if (result.outputPath) {
                console.log(`\n${colors.green}Extracted ${result.extractedLines.toLocaleString()} records to:${colors.reset}`);
                console.log(`  ${result.outputPath}`);
            } else {
                // Print to stdout
                for (const r of result.records) {
                    const iso = new Date(r.timestamp).toISOString();
                    console.log(`[${iso}] [${r.source}] [${r.level}] ${r.message}`);
                }
            }
            break;
        }

        case 'query': {
            const targetDir = positionals[0] || vaultDir;
            if (!secret) {
                console.error(`${colors.red}Error: Secret key is required to decrypt and query containers.${colors.reset}`);
                process.exit(1);
            }

            const filter = {
                query: flags.query || flags.q || undefined,
                levels: flags.level || flags.l || undefined,
                sources: flags.source || flags.s || undefined,
                limit: flags.limit ? Number(flags.limit) : 100
            };

            console.log(`${colors.blue}Querying vault:${colors.reset} ${path.resolve(targetDir)}`);
            const records = await queryVault(targetDir, secret, filter);

            console.log(`\n${colors.dim}Found ${records.length} matching records:${colors.reset}\n`);
            for (const r of records) {
                const time = new Date(r.timestamp).toISOString().replace('T', ' ').substring(0, 19);
                let lvlColor = colors.cyan;
                if (r.level === 'WARN') lvlColor = colors.yellow;
                if (r.level === 'ERROR' || r.level === 'FATAL') lvlColor = colors.red;
                if (r.level === 'DEBUG') lvlColor = colors.magenta;

                console.log(`${colors.gray}${time}${colors.reset} ${colors.blue}[${r.source}]${colors.reset} ${lvlColor}${r.level.padEnd(5)}${colors.reset} ${r.message}`);
            }
            break;
        }

        case 'tail': {
            const target = positionals[0] || vaultDir;
            if (!secret) {
                console.error(`${colors.red}Error: Secret key is required to tail vault logs.${colors.reset}`);
                process.exit(1);
            }

            const limit = flags.limit ? Number(flags.limit) : 50;
            const records = await queryVault(target, secret, { limit });

            for (const r of records.slice(-limit)) {
                const time = new Date(r.timestamp).toISOString().replace('T', ' ').substring(0, 19);
                let lvlColor = colors.cyan;
                if (r.level === 'WARN') lvlColor = colors.yellow;
                if (r.level === 'ERROR' || r.level === 'FATAL') lvlColor = colors.red;
                console.log(`${colors.gray}${time}${colors.reset} ${colors.blue}[${r.source}]${colors.reset} ${lvlColor}${r.level.padEnd(5)}${colors.reset} ${r.message}`);
            }
            break;
        }

        case 'help':
        default:
            printHelp();
            break;
    }
}

main().catch(err => {
    console.error(`\n${colors.red}MYCO Error: ${err.message}${colors.reset}`);
    process.exit(1);
});
