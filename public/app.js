/**
 * MYCO Vault - Embedded Web Viewer Client Application
 * Zero-dependency modern vanilla JS.
 */

// State
let vaultSecret = localStorage.getItem('myco_vault_secret') || '';
let currentRecords = [];
let eventSource = null;
let isStreaming = false;
let searchDebounceTimer = null;

// DOM Elements
const vaultSecretInput = document.getElementById('vaultSecretInput');
const toggleSecretVis = document.getElementById('toggleSecretVis');
const saveSecretBtn = document.getElementById('saveSecretBtn');

const statVaultDir = document.getElementById('statVaultDir');
const statContainerCount = document.getElementById('statContainerCount');
const statVaultSize = document.getElementById('statVaultSize');
const statSavedSpace = document.getElementById('statSavedSpace');

const searchQuery = document.getElementById('searchQuery');
const filterLevel = document.getElementById('filterLevel');
const filterContainer = document.getElementById('filterContainer');
const searchBtn = document.getElementById('searchBtn');
const liveStreamBtn = document.getElementById('liveStreamBtn');
const logsBody = document.getElementById('logsBody');
const logCounter = document.getElementById('logCounter');
const exportDecryptedBtn = document.getElementById('exportDecryptedBtn');

const refreshContainersBtn = document.getElementById('refreshContainersBtn');
const containersGrid = document.getElementById('containersGrid');
const containersSubinfo = document.getElementById('containersSubinfo');

const packSourceName = document.getElementById('packSourceName');
const packRawText = document.getElementById('packRawText');
const runPackBtn = document.getElementById('runPackBtn');
const packResult = document.getElementById('packResult');

const unpackSelectFile = document.getElementById('unpackSelectFile');
const runUnpackDownloadBtn = document.getElementById('runUnpackDownloadBtn');
const unpackResult = document.getElementById('unpackResult');

// Setup Secret Input
if (vaultSecret) {
    vaultSecretInput.value = vaultSecret;
    saveSecretBtn.textContent = 'Unlocked';
    saveSecretBtn.classList.remove('btn-primary');
    saveSecretBtn.classList.add('btn-secondary');
}

toggleSecretVis.addEventListener('click', () => {
    if (vaultSecretInput.type === 'password') {
        vaultSecretInput.type = 'text';
        toggleSecretVis.textContent = '🔒';
    } else {
        vaultSecretInput.type = 'password';
        toggleSecretVis.textContent = '👁️';
    }
});

saveSecretBtn.addEventListener('click', () => {
    const val = vaultSecretInput.value.trim();
    if (!val) {
        showTemporaryNotice(saveSecretBtn, 'Enter Key', 'btn-primary');
        return;
    }
    vaultSecret = val;
    localStorage.setItem('myco_vault_secret', vaultSecret);
    showTemporaryNotice(saveSecretBtn, 'Saved!', 'btn-secondary');
    loadStatus();
    loadLogs();
});

function showTemporaryNotice(btn, text, originalClass) {
    const origText = btn.textContent;
    btn.textContent = text;
    setTimeout(() => {
        btn.textContent = origText;
    }, 1500);
}

// Tab Switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        btn.classList.add('active');
        const targetId = btn.dataset.tab;
        const targetTab = document.getElementById(targetId);
        if (targetTab) {
            targetTab.classList.add('active');
        }

        if (targetId === 'tab-containers' || targetId === 'tab-pack') {
            loadStatus();
        }
    });
});

// Format file size
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format timestamp
function formatTime(ts) {
    if (!ts) return '--';
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').substring(0, 19);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Fetch Status & Containers
async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        statVaultDir.textContent = data.vaultDir || './vault';
        statVaultDir.title = data.vaultDir || '';
        statContainerCount.textContent = (data.fileCount || 0).toLocaleString();
        statVaultSize.textContent = formatBytes(data.totalSizeBytes || 0);

        // Update container selects
        const currentSelected = filterContainer.value;
        filterContainer.innerHTML = '<option value="">All Containers (Full Vault)</option>';
        unpackSelectFile.innerHTML = '';

        if (data.files && data.files.length > 0) {
            data.files.forEach(f => {
                const opt1 = document.createElement('option');
                opt1.value = f.name;
                opt1.textContent = `${f.name} (${formatBytes(f.size)})`;
                if (f.name === currentSelected) opt1.selected = true;
                filterContainer.appendChild(opt1);

                const opt2 = document.createElement('option');
                opt2.value = f.name;
                opt2.textContent = `${f.name} (${formatBytes(f.size)})`;
                unpackSelectFile.appendChild(opt2);
            });
        } else {
            const noOpt = document.createElement('option');
            noOpt.value = '';
            noOpt.textContent = 'No .myco containers found in vault';
            unpackSelectFile.appendChild(noOpt);
        }

        if (statSavedSpace) {
            statSavedSpace.textContent = `${data.overallSavedPercent || 0}% (${data.overallRatio || '1.00'}x)`;
        }
        if (containersSubinfo) {
            containersSubinfo.textContent = `${(data.fileCount || 0).toLocaleString()} containers · ${formatBytes(data.totalSavedBytes || 0)} space saved (${data.overallRatio || '1.00'}x ratio)`;
        }

        // Render Containers Archive Grid
        renderContainersGrid(data.files || []);
    } catch (err) {
        console.error('Failed to load status:', err);
    }
}

function renderContainersGrid(files) {
    if (!containersGrid) return;
    if (files.length === 0) {
        containersGrid.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                No .myco containers currently in vault directory.
            </div>
        `;
        return;
    }

    containersGrid.innerHTML = '';
    files.forEach(f => {
        const card = document.createElement('div');
        card.className = `myco-card ${f.isToday ? 'is-today' : ''}`;
        const savedPct = f.savedPercent || 0;
        const ratio = f.compressionRatio || '1.00';

        card.innerHTML = `
            <div class="myco-card-top">
                <div class="myco-card-icon">💽</div>
                <div class="myco-meta-wrap">
                    <div class="myco-filename">
                        <span>${escapeHtml(f.name)}</span>
                        ${f.isToday ? '<span class="tag-today-live">TODAY (LIVE)</span>' : ''}
                    </div>
                    <div class="myco-subinfo">
                        ${f.isToday ? 'Dual AES + ChaCha20 · Brotli Q7 (Live)' : 'Dual AES + ChaCha20 · Brotli Q11 (COL4)'}
                    </div>
                </div>
            </div>

            <div class="myco-storage-bar-wrap">
                <div class="myco-storage-bar-header">
                    <span style="color: var(--brand-green);">⚡ ${savedPct}% space saved</span>
                    <span style="color: var(--text-muted);">${formatBytes(f.size)}</span>
                </div>
                <div class="myco-storage-bar-bg" title="Raw uncompressed: ${formatBytes(f.rawBytes || f.size)} → Encrypted: ${formatBytes(f.size)} (${savedPct}% saved)">
                    <div class="myco-storage-bar-fill" style="width: ${Math.max(5, savedPct)}%;"></div>
                </div>
            </div>

            <div class="myco-card-footer">
                <div>
                    <strong style="color: var(--brand-green);">${ratio}x</strong> compression
                </div>
                <div style="color: var(--text-muted);">
                    ${(f.chunkCount || 1).toLocaleString()} chunks
                </div>
            </div>

            <div class="myco-card-actions">
                <button class="btn btn-secondary btn-small" onclick="quickViewContainer('${escapeHtml(f.name)}')">🔓 Read Logs</button>
                <button class="btn btn-primary btn-small" onclick="downloadContainerDecrypted('${escapeHtml(f.name)}')">📥 Download .log</button>
            </div>
        `;
        containersGrid.appendChild(card);
    });
}

// Quick View from Container Table
window.quickViewContainer = function(fileName) {
    filterContainer.value = fileName;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="tab-query"]').classList.add('active');
    document.getElementById('tab-query').classList.add('active');
    loadLogs();
};

// Download Decrypted Container from Table
window.downloadContainerDecrypted = function(fileName) {
    unpackSelectFile.value = fileName;
    triggerUnpackDownload();
};

// Load & Search Decrypted Logs
async function loadLogs() {
    const secret = vaultSecretInput.value.trim() || vaultSecret;
    if (!secret) {
        logsBody.innerHTML = `
            <div class="empty-state">
                Please enter your <strong>VAULT_SECRET</strong> above to decrypt records.
            </div>
        `;
        logCounter.textContent = '0 records loaded';
        exportDecryptedBtn.style.display = 'none';
        return;
    }

    logsBody.innerHTML = `
        <div class="empty-state">
            Decrypting & scanning containers...
        </div>
    `;

    try {
        const payload = {
            secret,
            query: searchQuery.value.trim() || undefined,
            levels: filterLevel.value || undefined,
            file: filterContainer.value || undefined,
            limit: 1000
        };

        const res = await fetch('/api/query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Vault-Secret': secret
            },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok || data.error) {
            logsBody.innerHTML = `
                <div class="empty-state" style="color: var(--brand-red);">
                    <strong>Decryption Error:</strong> ${escapeHtml(data.error || 'Failed to decrypt')}
                </div>
            `;
            logCounter.textContent = '0 records loaded';
            exportDecryptedBtn.style.display = 'none';
            return;
        }

        currentRecords = data.records || [];
        renderRecords(currentRecords);
    } catch (err) {
        logsBody.innerHTML = `
            <div class="empty-state" style="color: var(--brand-red);">
                Network error: ${escapeHtml(err.message)}
            </div>
        `;
    }
}

function renderRecords(records) {
    if (!records || records.length === 0) {
        logsBody.innerHTML = `
            <div class="empty-state">
                No log entries matched your query filters.
            </div>
        `;
        logCounter.textContent = '0 records loaded';
        exportDecryptedBtn.style.display = 'none';
        return;
    }

    const fragment = document.createDocumentFragment();
    for (const r of records) {
        const row = document.createElement('div');
        row.className = 'log-row';

        const time = formatTime(r.timestamp);
        const lvl = (r.level || 'INFO').toUpperCase();
        let lvlClass = 'INFO';
        if (lvl === 'WARN') lvlClass = 'WARN';
        else if (lvl === 'ERROR' || lvl === 'FATAL') lvlClass = 'ERROR';
        else if (lvl === 'DEBUG' || lvl === 'TRACE') lvlClass = 'DEBUG';

        row.innerHTML = `
            <div class="col-time">${escapeHtml(time)}</div>
            <div class="col-source" title="${escapeHtml(r.source)}">${escapeHtml(r.source)}</div>
            <div class="col-level"><span class="level-badge ${lvlClass}">${escapeHtml(lvl)}</span></div>
            <div class="col-msg">${escapeHtml(r.message)}</div>
        `;
        fragment.appendChild(row);
    }

    logsBody.innerHTML = '';
    logsBody.appendChild(fragment);
    logCounter.textContent = `${records.length.toLocaleString()} records loaded`;
    exportDecryptedBtn.style.display = 'inline-block';
}

// Live SSE Stream Toggle
liveStreamBtn.addEventListener('click', () => {
    if (isStreaming) {
        stopLiveStream();
    } else {
        startLiveStream();
    }
});

function startLiveStream() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/stream');
    isStreaming = true;
    liveStreamBtn.textContent = '⚡ Live Stream: ON';
    liveStreamBtn.classList.remove('btn-secondary');
    liveStreamBtn.classList.add('btn-primary');

    eventSource.onmessage = (e) => {
        try {
            const record = JSON.parse(e.data);
            appendStreamRecord(record);
        } catch (err) {
            console.error('SSE JSON error:', err);
        }
    };

    eventSource.onerror = () => {
        console.warn('SSE connection disconnected. Reconnecting...');
    };
}

function stopLiveStream() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    isStreaming = false;
    liveStreamBtn.textContent = '⚡ Live Stream: OFF';
    liveStreamBtn.classList.remove('btn-primary');
    liveStreamBtn.classList.add('btn-secondary');
}

function appendStreamRecord(r) {
    // Check level filter
    const activeLevel = filterLevel.value;
    if (activeLevel && (r.level || '').toUpperCase() !== activeLevel) return;

    // Check search filter
    const q = searchQuery.value.trim().toLowerCase();
    if (q) {
        const matches = (r.message && r.message.toLowerCase().includes(q)) ||
                        (r.source && r.source.toLowerCase().includes(q));
        if (!matches) return;
    }

    // Remove empty state if present
    const empty = logsBody.querySelector('.empty-state');
    if (empty) logsBody.innerHTML = '';

    const row = document.createElement('div');
    row.className = 'log-row';

    const time = formatTime(r.timestamp);
    const lvl = (r.level || 'INFO').toUpperCase();
    let lvlClass = 'INFO';
    if (lvl === 'WARN') lvlClass = 'WARN';
    else if (lvl === 'ERROR' || lvl === 'FATAL') lvlClass = 'ERROR';
    else if (lvl === 'DEBUG') lvlClass = 'DEBUG';

    row.innerHTML = `
        <div class="col-time">${escapeHtml(time)}</div>
        <div class="col-source" title="${escapeHtml(r.source)}">${escapeHtml(r.source)}</div>
        <div class="col-level"><span class="level-badge ${lvlClass}">${escapeHtml(lvl)}</span></div>
        <div class="col-msg">${escapeHtml(r.message)}</div>
    `;

    logsBody.appendChild(row);
    currentRecords.push(r);
    logCounter.textContent = `${currentRecords.length.toLocaleString()} records loaded`;
    logsBody.scrollTop = logsBody.scrollHeight;
}

// Export Decrypted View to File
exportDecryptedBtn.addEventListener('click', () => {
    if (!currentRecords || currentRecords.length === 0) return;
    const text = currentRecords.map(r => {
        const time = formatTime(r.timestamp);
        return `[${time}] [${r.source}] [${r.level}] ${r.message}`;
    }).join('\n');

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u;
    a.download = `myco-export-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(u);
});

// Run Manual Packer
runPackBtn.addEventListener('click', async () => {
    const secret = vaultSecretInput.value.trim() || vaultSecret;
    const content = packRawText.value;
    const source = packSourceName.value.trim() || 'manual';

    if (!secret) {
        packResult.className = 'result-msg error';
        packResult.textContent = 'Secret is required to encrypt log container.';
        return;
    }

    if (!content.trim()) {
        packResult.className = 'result-msg error';
        packResult.textContent = 'Please paste or write raw log lines to pack.';
        return;
    }

    runPackBtn.disabled = true;
    runPackBtn.textContent = 'Encrypting...';
    packResult.style.display = 'none';

    try {
        const res = await fetch('/api/pack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, content, source })
        });

        const data = await res.json();
        if (data.success) {
            packResult.className = 'result-msg success';
            packResult.textContent = `Successfully encrypted & packed ${data.recordsPacked} records into ${data.fileName}!`;
            packRawText.value = '';
            loadStatus();
        } else {
            packResult.className = 'result-msg error';
            packResult.textContent = `Pack failed: ${data.error}`;
        }
    } catch (err) {
        packResult.className = 'result-msg error';
        packResult.textContent = `Network error: ${err.message}`;
    } finally {
        runPackBtn.disabled = false;
        runPackBtn.textContent = 'Encrypt & Save to Vault';
    }
});

// Run Container Decryptor & Downloader
runUnpackDownloadBtn.addEventListener('click', () => {
    triggerUnpackDownload();
});

async function triggerUnpackDownload() {
    const secret = vaultSecretInput.value.trim() || vaultSecret;
    const file = unpackSelectFile.value;

    if (!secret || !file) {
        unpackResult.className = 'result-msg error';
        unpackResult.textContent = 'Please specify a container and ensure secret is set.';
        return;
    }

    runUnpackDownloadBtn.disabled = true;
    runUnpackDownloadBtn.textContent = 'Decrypting...';
    unpackResult.style.display = 'none';

    try {
        const res = await fetch('/api/unpack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, file })
        });

        if (!res.ok) {
            const errJson = await res.json().catch(() => ({}));
            throw new Error(errJson.error || `HTTP ${res.status}`);
        }

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.replace(/\.myco$/, '.log');
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        unpackResult.className = 'result-msg success';
        unpackResult.textContent = `Container decrypted and downloaded as ${a.download}.`;
    } catch (err) {
        unpackResult.className = 'result-msg error';
        unpackResult.textContent = `Decryption failed: ${err.message}`;
    } finally {
        runUnpackDownloadBtn.disabled = false;
        runUnpackDownloadBtn.textContent = 'Download Decrypted .log';
    }
}

// Event Listeners for Filters
searchBtn.addEventListener('click', loadLogs);
refreshContainersBtn.addEventListener('click', loadStatus);
filterLevel.addEventListener('change', loadLogs);
filterContainer.addEventListener('change', loadLogs);

searchQuery.addEventListener('input', () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(loadLogs, 300);
});

// Initialization
loadStatus();
if (vaultSecret) {
    loadLogs();
}
