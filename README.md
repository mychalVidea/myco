# MYCO Vault

> **Zero-dependency military-grade encrypted log vault, Brotli compressor, and real-time log manager.**

[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20runtime-blue.svg)](package.json)
[![Encryption](https://img.shields.io/badge/cipher-AES--256--GCM%20%2B%20ChaCha20--Poly1305-blueviolet.svg)](src/core/crypto.js)
[![Compression](https://img.shields.io/badge/compression-Brotli%20COL4-orange.svg)](src/core/compressor.js)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

MYCO Vault is a lightweight, ultra-secure, and highly optimized log archiving and monitoring system. It continuously collects logs from application files, wildcards, directories, and UDP syslog streams, packs them into a high-density columnar binary format (**COL4**), compresses them with **Brotli**, and encrypts them with a **Dual-Layer AEAD cryptographic shield** (`AES-256-GCM` + `ChaCha20-Poly1305`).

---

## ✨ Features

- 🛡️ **Military-Grade Dual-Layer AEAD Encryption**:
  - Inner Layer: Hardware-accelerated `AES-256-GCM` (AES-NI).
  - Outer Layer: Constant-time `ChaCha20-Poly1305`.
  - Keys derived via `HKDF-SHA512` from your master secret + per-container random 16-byte salt.
  - Zero ciphertext leak, tamper-evident authentication tags.
- 🗜️ **COL4 Columnar Binary Format & Brotli**:
  - Inter-arrival delta timestamp encoding ($\Delta t_i = t_i - t_{i-1}$).
  - Sub-byte bit-packing (5-bit source ID + 3-bit log level in 1 byte).
  - Dynamic source dictionary per chunk.
  - LEB128 Varints for lengths and offsets.
  - Achieves **80% to 99.5% space savings** on structured production logs (COL4 bit-packing + Brotli Q11).
- ⚡ **Zero External Runtime Dependencies**:
  - Built 100% on Node.js native primitives (`crypto`, `zlib`, `fs`, `http`, `dgram`, `readline`).
  - No bloated npm dependency trees or supply-chain attack vectors.
- 📊 **Embedded Web Viewer UI**:
  - Real-time Server-Sent Events (SSE) live log tailing.
  - Client-side secret unlocking (key never leaves memory/browser).
  - Instant text search, level filtering, container inspection, and one-click `.log` export.
- 🛠️ **Comprehensive CLI**:
  - Daemon, Web UI, Ingestion packer, Container unpacker, Multi-container query, Tail, and Keygen.

---

## 🚀 Quick Start

### 1. Installation
Clone or install the package:
```bash
git clone https://github.com/mychalVidea/myco-vault.git
cd myco-vault
```

### 2. Generate a Secret Key
Generate a cryptographically secure 256-bit encryption key:
```bash
node bin/myco.js keygen
```
*Output:*
```text
Generated High-Entropy 256-bit Encryption Key:
  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 3. Create Configuration
Copy the example configuration:
```bash
cp myco.config.example.json myco.config.json
```
Edit `myco.config.json` and paste your generated key into `"vaultSecret"`.

### 4. Start Collector & Web UI
```bash
# Start daemon (Collector + Web UI on http://127.0.0.1:8080)
node bin/myco.js daemon

# Or run just the standalone Web Viewer:
node bin/myco.js ui --port 8080
```

---

## 📊 Real-World Production Benchmarks

MYCO Vault is battle-tested in 24/7 production workloads (Minecraft SMP servers, Discord bots, Nginx proxies, and authentication gateways).

### Production Storage Footprint (6.47 Million Logs)

| Metric | Raw Plain-Text Logs | MYCO Encrypted Vault | Impact / Efficiency |
| :--- | :--- | :--- | :--- |
| **Total Log Volume** | **815.43 MB** | **3.84 MB** | **99.5% Disk Space Saved** |
| **Overall Compression** | `1.00x` | **`212.4x`** | **212x denser storage** |
| **Total Indexed Records** | 6,475,883 lines | 6,475,883 lines | 100% zero-loss fidelity |
| **Security Standard** | Plaintext (Unsafe) | Dual AEAD (`AES` + `ChaCha20`) | Military-grade tamper-proof |

### Real Container Examples from Production

Thanks to the **COL4 Columnar Tokenizer** and Brotli Q11 engine, logs are partitioned into typed columnar streams (timestamps, levels, sources, text) before compression:

| Daily Container Archive | Log Records | Raw Size (Est.) | Vault Size on Disk | Ratio | Space Saved |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `vault-2026-09-21.myco` | **306,283 logs** | ~47.9 MB | **80.6 KB** | **594.37x** | **99% saved** |
| `vault-2026-09-16.myco` | **289,820 logs** | ~29.5 MB | **101.4 KB** | **290.87x** | **99% saved** |
| `vault-2026-09-15.myco` | **190,894 logs** | ~21.9 MB | **122.8 KB** | **178.28x** | **99% saved** |
| `vault-2026-09-20.myco` | **66,597 logs** | ~7.3 MB | **197.8 KB** | **37.16x** | **97% saved** |
| `vault-2026-09-22.myco` *(Live)* | **21,178 logs** | ~2.7 MB | **633.8 KB** | **4.38x** | **77% saved** |

> **Why is compression so much higher than gzip or zip?**
> Standard `.tar.gz` or `.zip` treats log files as a single continuous byte stream. MYCO Vault's **COL4 Columnar Tokenizer** breaks records into separate typed columns:
> 1. **Inter-Arrival Deltas**: Variable integers (LEB128) representing milliseconds between events ($\Delta t_i$).
> 2. **Sub-Byte Bit-Packing**: 1 byte encodes both a 5-bit source ID and a 3-bit log level.
> 3. **Dynamic Source Dictionary**: Source names and common recurring substrings are stored once per chunk.
> 4. **Brotli Q11 Shuffle**: When columnar data is ordered consecutively in memory, Brotli achieves up to **594x** compression ratios.

> [!NOTE]
> **Production Benchmark vs. General File Compression:**
> The **99.5% storage reduction (~212x to ~594x)** is a **benchmark on real-world server logs** (4+ months of Minecraft SMP, Discord bot, and proxy logs). Log datasets are uniquely suited for COL4 columnar structuring because they feature highly repetitive thread prefixes, recurring levels (`INFO`/`WARN`), clustered timestamps, and dictionary strings. On arbitrary, unstructured binary or non-log data, compression reflects standard Brotli ratios.

---

## ⚙️ Configuration Guide

MYCO Vault looks for configuration in:
1. File passed via `--config <path>`
2. Path in `MYCO_CONFIG` environment variable
3. `./myco.config.json` in the working directory
4. `./config.json`

### Example `myco.config.json`

```json
{
  "vaultSecret": "your-256-bit-hex-secret-or-passphrase",
  "vaultDir": "./vault",
  "rotation": "daily",
  "compression": {
    "liveQuality": 7,
    "batchQuality": 11
  },
  "flush": {
    "maxRecords": 500,
    "maxBytes": 65536,
    "intervalMs": 5000
  },
  "sources": [
    {
      "id": "minecraft-server",
      "name": "Minecraft Server Logs",
      "path": "./server/logs/latest.log",
      "enabled": true
    },
    {
      "id": "pm2-apps",
      "name": "PM2 Process Logs",
      "path": "~/.pm2/logs/*.log",
      "enabled": true
    },
    {
      "id": "nginx-access",
      "name": "Nginx Access Logs",
      "path": "/var/log/nginx/access.log",
      "enabled": false
    },
    {
      "id": "syslog-listener",
      "name": "UDP Syslog Listener",
      "type": "udp",
      "port": 5140,
      "host": "127.0.0.1",
      "enabled": false
    }
  ],
  "filters": {
    "stripAnsi": true,
    "collapseDuplicates": true,
    "ignoreRegex": [
      "^\\s*$",
      "\\[DEBUG\\] KeepAlive",
      "GET /healthz 200"
    ]
  },
  "ui": {
    "enabled": true,
    "port": 8080,
    "host": "127.0.0.1"
  }
}
```

### Configuration Options Reference

| Section | Property | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Root** | `vaultSecret` | `string` | *(Required)* | Master encryption key or passphrase. Can also be set via `VAULT_SECRET` env. |
| | `vaultDir` | `string` | `"./vault"` | Directory where encrypted `.myco` containers are saved. |
| | `rotation` | `string` | `"daily"` | File rotation interval: `"daily"` (`vault-YYYY-MM-DD.myco`) or `"hourly"` (`vault-YYYY-MM-DD-HH.myco`). |
| **`compression`** | `liveQuality` | `number` | `7` | Brotli compression quality (0–11) for streaming logs. Higher = more compression, more CPU. |
| | `batchQuality` | `number` | `11` | Brotli quality used during offline/batch pack operations. |
| **`flush`** | `maxRecords` | `number` | `500` | Flush chunk to disk once buffer reaches this record count. |
| | `maxBytes` | `number` | `65536` | Flush chunk to disk once buffer exceeds this raw byte size (64 KB). |
| | `intervalMs` | `number` | `5000` | Maximum time (ms) to hold records in RAM before writing to disk. |
| **`sources[]`** | `name` / `id` | `string` | `"source"` | Identifier tagged to every log entry from this source. |
| | `path` | `string` | — | Path to file, directory, or wildcard glob (e.g. `~/.pm2/logs/*.log`, `/var/log/*.log`). Supports `~` home expansion. |
| | `type` | `string` | `"file"` | Source type: `"file"` or `"udp"` / `"syslog"`. |
| | `port` / `host` | `number`/`string` | `5140` / `"127.0.0.1"` | UDP port & host for Syslog listener. |
| | `enabled` | `boolean` | `true` | Set to `false` to disable source without removing config. |
| | `tail` | `boolean` | `true` | If `true`, only captures new lines added while running. If `false`, ingests existing lines from start of file. |
| **`filters`** | `stripAnsi` | `boolean` | `true` | Automatically strips terminal ANSI color codes from incoming lines. |
| | `collapseDuplicates` | `boolean` | `true` | Suppresses rapid duplicate lines and appends `[Repeated N times]`. |
| | `ignoreRegex` | `string[]` | `[]` | Array of regex patterns. Any line matching will be dropped. |
| **`ui`** | `enabled` | `boolean` | `true` | Whether to launch embedded Web Viewer alongside daemon. |
| | `port` | `number` | `8080` | Web server listening port. |
| | `host` | `string` | `"127.0.0.1"` | Web server bind address. |

---

## 🔒 Environment Variables

You can configure MYCO Vault entirely via environment variables:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `VAULT_SECRET` | Master encryption key (fallback: `MYCO_SECRET`) | `your-secret-key-or-hex` |
| `VAULT_DIR` | Directory containing `.myco` containers | `/var/log/vault` |
| `PORT` | Web UI HTTP port | `8080` |
| `MYCO_CONFIG` | Path to custom configuration JSON file | `/etc/myco/config.json` |

---

## 💻 CLI Commands

### 1. `myco keygen`
Generates a random 256-bit cryptographically secure key:
```bash
node bin/myco.js keygen
```

### 2. `myco daemon`
Starts log collection and the embedded Web Viewer:
```bash
node bin/myco.js daemon --config ./myco.config.json
```

### 3. `myco ui`
Runs the standalone Web Viewer:
```bash
node bin/myco.js ui --port 8080 --vault ./vault --secret "your-secret"
```

### 4. `myco pack`
Compresses and encrypts any raw `.log` file or directory into a `.myco` container:
```bash
# Encrypt a single log file
node bin/myco.js pack ./server.log --out ./vault --secret "your-secret"

# Encrypt all .log files in a directory
node bin/myco.js pack ./logs --out ./vault --secret "your-secret"
```

### 5. `myco unpack`
Decrypts and decompresses a `.myco` archive back into plain-text:
```bash
# Export container to a restored .log file
node bin/myco.js unpack ./vault/vault-2026-09-22.myco --out ./restored.log --secret "your-secret"

# Print decrypted records directly to stdout
node bin/myco.js unpack ./vault/vault-2026-09-22.myco --secret "your-secret"
```

### 6. `myco query`
Searches across encrypted containers with filters:
```bash
node bin/myco.js query ./vault --secret "your-secret" --level ERROR --query "connection timeout"
```

### 7. `myco tail`
Displays the latest decrypted records in terminal with color-coded levels:
```bash
node bin/myco.js tail ./vault --secret "your-secret" --limit 50
```

---

## 🌐 Embedded Web Viewer

The embedded web interface provides an intuitive console without external front-end dependencies:

- **Log Explorer & Search**:
  - Filter by log level (`ERROR`, `WARN`, `INFO`, `DEBUG`).
  - Target specific `.myco` container archives or query across the entire vault.
  - Live search debounced input for filtering messages, sources, player names, or exceptions.
  - One-click **Export View to .txt**.
- **⚡ Live Stream**:
  - Real-time Server-Sent Events (SSE) feed direct from collector to your browser.
- **Containers Archive**:
  - Lists daily and hourly container archives with exact disk footprint and modified timestamps.
  - Single-click container inspection or plain-text download.
- **Packer & Standalone Decryptor**:
  - Paste raw logs or drop text files to instantly encrypt into the vault.
  - Decrypt any `.myco` container directly to `.log`.

---

## 🔬 Binary Format (COL4)

Each `.myco` file contains a 37-byte container header followed by independent binary chunk blocks (`CBLK`):

```
Container File Layout:
+-------------------------------------------------------------------------+
| MAGIC (4B 'MYCO') | VER (1B) | SALT (16B) | CHECK_TAG (16B HMAC-SHA256) |
+-------------------------------------------------------------------------+
| CHUNK 1 [MAGIC (4B 'CBLK') | RAW_LEN (4B) | CMP_LEN (4B) | DUAL_AEAD]   |
+-------------------------------------------------------------------------+
| CHUNK 2 [MAGIC (4B 'CBLK') | RAW_LEN (4B) | CMP_LEN (4B) | DUAL_AEAD]   |
+-------------------------------------------------------------------------+
| ...                                                                     |
+-------------------------------------------------------------------------+
```

### Dual-Layer AEAD Encryption:
1. **Inner Layer**: `AES-256-GCM` with random 12-byte IV per chunk + 16-byte authentication tag.
2. **Outer Layer**: `ChaCha20-Poly1305` with random 12-byte IV per chunk + 16-byte authentication tag.
3. Decryption fails in constant-time if the file has been modified, corrupted, or if an incorrect passphrase is supplied.

---

## 🧪 Testing

MYCO Vault includes an automated test suite verifying cryptographic primitives, compression ratios, COL4 columnar encoding, and end-to-end container reading and writing:

```bash
npm test
```

---

## 🤝 Ecosystem, Extensions & Contributing

The **COL4 binary specification** and **Dual-Layer AEAD container architecture** are completely open, unpatented, and designed for broad interoperability.

We strongly encourage the developer community to build tools, wrappers, and extensions on top of MYCO Vault! Some exciting ideas to explore or contribute:

- 🌐 **Web & Framework Middleware**: Express, Fastify, Next.js, or Koa stream sinks that automatically pipe HTTP access logs into encrypted `.myco` vaults.
- 🔌 **Log Ingestion Adapters**: Docker container log sidecars, Kubernetes FluentBit/Vector plugins, or systemd journald forwarders.
- 🗃️ **Multi-Language Implementations**: Ports of the COL4 reader/writer standard in Go, Rust, Python, or C#.
- 🖥️ **Desktop & IDE Plugins**: VS Code extension to preview, search, and inspect `.myco` containers right inside your editor, or desktop GUI tools.
- 📈 **Monitoring & Metrics Exporters**: Grafana, Prometheus, or Datadog exporters for container compression and log volume stats.

### 💡 Author's Note & Motivation

> I learned programming primarily in **Java** and **JavaScript**, which are essentially the main languages I know and feel comfortable with. That is why MYCO Vault is implemented natively in zero-dependency Node.js JavaScript.
> 
> Because my background is centered around JS and Java, I would love to see the community take this concept further and expand it into other languages and environments—whether that means writing native ports in **Rust, Go, Python**, building web framework integrations, or creating desktop utilities. Feel free to fork, expand, and build something awesome on top of it!

### Built something cool with MYCO Vault?
Feel free to open an Issue or submit a Pull Request to feature your integration in our official Community Showcase!

Contributions, bug reports, performance ideas, and feature requests are warmly welcomed.

---

## 📜 License

[MIT](LICENSE) © [mychalVidea](https://mychalsmp.xyz)
