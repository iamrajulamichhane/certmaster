'use strict';

// Client-side limits mirror the server (server is the source of truth).
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB
const ALLOWED_EXT = ['pem', 'der', 'crt', 'cer', 'p12', 'pfx', 'p7b', 'p7c'];

// State
let currentFile = null;
let selectedTarget = null;
let selectedSupportsPw = false;
let lastObjectUrl = null;
let lastPwUrl = null;

// Elements
const dropZone        = document.getElementById('drop-zone');
const fileInput       = document.getElementById('file-input');
const errorBanner     = document.getElementById('error-banner');
const errorText       = document.getElementById('error-text');
const convertCard     = document.getElementById('convert-card');
const fileNameDisplay = document.getElementById('file-name-display');
const fileSizeDisplay = document.getElementById('file-size-display');
const detectedLabel   = document.getElementById('detected-fmt-label');
const targetGrid      = document.getElementById('target-grid');
const btnConvert      = document.getElementById('btn-convert');
const btnConvertText  = document.getElementById('btn-convert-text');
const downloadSection = document.getElementById('download-section');
const downloadLink    = document.getElementById('download-link');
const resultFilename  = document.getElementById('result-filename');
const btnReset        = document.getElementById('btn-reset');
const dropHeading     = dropZone.querySelector('h3');

const sourcePwBlock   = document.getElementById('source-pw-block');
const sourcePwInput   = document.getElementById('source-pw-input');
const sourcePwFile    = document.getElementById('source-pw-file');
const outputPwBlock   = document.getElementById('output-pw-block');
const outputPwInput   = document.getElementById('output-pw-input');
const outputPwSave    = document.getElementById('output-pw-save');
const pwDownloadRow   = document.getElementById('pw-download-row');
const pwDownloadLink  = document.getElementById('pw-download-link');

// ── Drag & drop ──
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFile(fileInput.files[0]);
});

// Password file -> read into the source password input
sourcePwFile.addEventListener('change', async () => {
  const f = sourcePwFile.files[0];
  if (!f) return;
  if (f.size > 4096) { showError('Password file is too large.'); return; }
  const text = (await f.text()).trim();
  sourcePwInput.value = text;
});

// ── Reset everything (used on new upload AND the manual reset link) ──
function resetUI() {
  selectedTarget = null;
  selectedSupportsPw = false;
  convertCard.classList.add('hidden');
  downloadSection.classList.add('hidden');
  sourcePwBlock.classList.add('hidden');
  outputPwBlock.classList.add('hidden');
  pwDownloadRow.classList.add('hidden');
  sourcePwInput.value = '';
  outputPwInput.value = '';
  outputPwSave.checked = false;
  targetGrid.textContent = '';
  clearError();
  if (lastObjectUrl) { URL.revokeObjectURL(lastObjectUrl); lastObjectUrl = null; }
  if (lastPwUrl) { URL.revokeObjectURL(lastPwUrl); lastPwUrl = null; }
}

// ── Client-side validation ──
function validateFile(file) {
  if (file.size === 0) return 'File is empty.';
  if (file.size > MAX_FILE_SIZE) return 'File too large (max 2 MB).';
  const ext = file.name.includes('.') ? file.name.split('.').pop().toLowerCase() : '';
  if (ext && !ALLOWED_EXT.includes(ext)) {
    return `Unsupported file type ".${ext}". Allowed: ${ALLOWED_EXT.join(', ')}.`;
  }
  return null;
}

async function handleFile(file) {
  // Auto-refresh: clear all previous results the instant a new file arrives.
  resetUI();

  const vErr = validateFile(file);
  if (vErr) { currentFile = null; showError(vErr); return; }

  currentFile = file;
  setLoading(true);

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch('/api/detect', { method: 'POST', body: fd });
    const data = await safeJson(res);
    if (!res.ok) throw new Error(data.detail || 'Detection failed.');
    showDetectResult(data);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

function showDetectResult(data) {
  fileNameDisplay.textContent = data.filename;
  fileSizeDisplay.textContent = formatBytes(data.size);
  detectedLabel.textContent   = data.detected_format;

  // Source password prompt for encrypted PKCS#12/PFX
  sourcePwBlock.classList.toggle('hidden', !data.needs_password);

  targetGrid.textContent = '';
  selectedTarget = null;
  selectedSupportsPw = false;

  (data.possible_targets || []).forEach((t) => {
    const btn = document.createElement('button');
    btn.className = 'target-btn';
    btn.type = 'button';
    btn.dataset.supportsPw = t.supports_password ? '1' : '0';

    const fmt = document.createElement('div');
    fmt.className = 'tb-fmt';
    fmt.textContent = t.format;

    const desc = document.createElement('div');
    desc.className = 'tb-desc';
    desc.textContent = t.label;

    btn.appendChild(fmt);
    btn.appendChild(desc);
    btn.addEventListener('click', () => selectTarget(t.format, t.supports_password, btn));
    targetGrid.appendChild(btn);
  });

  convertCard.classList.remove('hidden');
  downloadSection.classList.add('hidden');
  btnConvert.disabled = true;
  btnConvertText.textContent = 'Select a target format';
}

function selectTarget(fmt, supportsPw, el) {
  selectedTarget = fmt;
  selectedSupportsPw = supportsPw;
  document.querySelectorAll('.target-btn').forEach((b) => b.classList.remove('selected'));
  el.classList.add('selected');
  outputPwBlock.classList.toggle('hidden', !supportsPw);
  btnConvert.disabled = false;
  btnConvertText.textContent = `Convert to ${fmt}`;
}

// ── Convert ──
btnConvert.addEventListener('click', async () => {
  if (!currentFile || !selectedTarget) return;

  // If source needs a password, require it before sending.
  if (!sourcePwBlock.classList.contains('hidden') && !sourcePwInput.value.trim()) {
    showError('Please enter the password for this protected file.');
    return;
  }

  setConverting(true);
  clearError();
  downloadSection.classList.add('hidden');

  const fd = new FormData();
  fd.append('file', currentFile);
  fd.append('target_format', selectedTarget);
  if (!sourcePwBlock.classList.contains('hidden') && sourcePwInput.value) {
    fd.append('password', sourcePwInput.value);
  }
  const outPw = (selectedSupportsPw && outputPwInput.value) ? outputPwInput.value : '';
  if (outPw) fd.append('output_password', outPw);

  try {
    const res = await fetch('/api/convert', { method: 'POST', body: fd });
    if (!res.ok) {
      const data = await safeJson(res);
      if (res.status === 401 && data.needs_password) {
        sourcePwBlock.classList.remove('hidden');
      }
      throw new Error(data.detail || 'Conversion failed.');
    }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename="([^"]+)"/);
    const fname = m ? m[1] : `certificate.${selectedTarget.toLowerCase()}`;

    if (lastObjectUrl) URL.revokeObjectURL(lastObjectUrl);
    lastObjectUrl = URL.createObjectURL(blob);
    downloadLink.href = lastObjectUrl;
    downloadLink.download = fname;
    resultFilename.textContent = fname;

    // Offer the password as a downloadable .txt if requested
    pwDownloadRow.classList.add('hidden');
    if (lastPwUrl) { URL.revokeObjectURL(lastPwUrl); lastPwUrl = null; }
    if (outPw && outputPwSave.checked) {
      const pwBlob = new Blob([outPw], { type: 'text/plain' });
      lastPwUrl = URL.createObjectURL(pwBlob);
      pwDownloadLink.href = lastPwUrl;
      pwDownloadLink.download = fname.replace(/\.[^.]+$/, '') + '.password.txt';
      pwDownloadRow.classList.remove('hidden');
    }

    downloadSection.classList.remove('hidden');
  } catch (err) {
    showError(err.message);
  } finally {
    setConverting(false);
  }
});

// ── Manual reset link ──
btnReset.addEventListener('click', () => {
  currentFile = null;
  resetUI();
  fileInput.value = '';
});

// ── Helpers ──
async function safeJson(res) {
  try { return await res.json(); } catch { return {}; }
}
function showError(msg) { errorText.textContent = msg; errorBanner.classList.remove('hidden'); }
function clearError() { errorBanner.classList.add('hidden'); }
function setLoading(on) {
  dropHeading.textContent = on ? 'Analysing certificate…' : 'Drop certificate here or click to browse';
}
function setConverting(on) {
  if (on) {
    btnConvert.disabled = true;
    btnConvertText.textContent = '';
    const sp = document.createElement('span');
    sp.className = 'spinner';
    btnConvertText.appendChild(sp);
    btnConvertText.appendChild(document.createTextNode('\u00A0 Converting…'));
  } else {
    btnConvert.disabled = false;
    btnConvertText.textContent = selectedTarget ? `Convert to ${selectedTarget}` : 'Select a target format';
  }
}
function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}
