/**
 * app.js
 *
 * UI wiring for QR Sentry. Handles:
 *  - switching between the home / scanner / results views
 *  - driving the html5-qrcode camera and file scanners
 *  - rendering analysis results from QRAnalyzer
 *  - a small "recent scans" history and optional Safe Browsing setting,
 *    both stored only in this browser's localStorage
 *
 * Security notes:
 *  - Scanned content (`result.raw`) is only ever written to the page via
 *    `textContent`, never `innerHTML`, so a malicious QR code cannot
 *    inject markup or scripts.
 *  - Links are only made clickable for http/https/non-web schemes that
 *    QRAnalyzer does not classify as dangerous (javascript:, data:, etc.).
 *    Opening a link always goes through `window.confirm` and
 *    `window.open(..., 'noopener,noreferrer')`.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  // ---- DOM references -------------------------------------------------
  const viewHome = $('view-home');
  const viewScanner = $('view-scanner');
  const viewResults = $('view-results');

  const startScanBtn = $('start-scan-btn');
  const cancelScanBtn = $('cancel-scan-btn');
  const scannerStatus = $('scanner-status');
  const homeStatus = $('home-status');
  const fileInput = $('file-input');

  const verdictCard = $('verdict-card');
  const verdictRing = $('verdict-ring');
  const verdictScore = $('verdict-score');
  const verdictLabel = $('verdict-label');
  const verdictSub = $('verdict-sub');

  const scannedContent = $('scanned-content');
  const copyBtn = $('copy-btn');
  const openBtn = $('open-btn');
  const copyFeedback = $('copy-feedback');

  const findingsList = $('findings-list');
  const safebrowsingStatus = $('safebrowsing-status');

  const scanAgainBtn = $('scan-again-btn');

  const recentList = $('recent-list');
  const recentEmpty = $('recent-empty');
  const clearHistoryBtn = $('clear-history-btn');

  const settingsBtn = $('settings-btn');
  const settingsDialog = $('settings-dialog');
  const settingsForm = $('settings-form');
  const settingsCancel = $('settings-cancel');
  const safeBrowsingEndpointInput = $('safebrowsing-key');

  // ---- Constants --------------------------------------------------------
  const SCANNER_ELEMENT_ID = 'qr-reader';
  const HISTORY_KEY = 'qrSentry.history';
  const SETTINGS_KEY = 'qrSentry.settings';
  const MAX_HISTORY = 8;

  const SEVERITY_LABELS = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info'
  };

  // ---- State --------------------------------------------------------------
  let html5QrCode = null;
  let fileScanner = null;
  let acceptingScans = false;
  let currentOpenUrl = null; // URL object, only set when "Open" is safe to show
  let currentVerdict = 'low';

  // -----------------------------------------------------------------------
  // View management
  // -----------------------------------------------------------------------
  function showView(view) {
    for (const v of [viewHome, viewScanner, viewResults]) {
      v.hidden = v !== view;
    }
    window.scrollTo(0, 0);
  }

  // -----------------------------------------------------------------------
  // Settings (stored locally only)
  // -----------------------------------------------------------------------
  function loadSettings() {
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (_) {
      return {};
    }
  }

  function saveSettings(settings) {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch (_) {
      // localStorage unavailable (e.g. private browsing) — fail silently.
    }
  }

  settingsBtn.addEventListener('click', () => {
    const settings = loadSettings();
    safeBrowsingEndpointInput.value = settings.workerEndpoint || '';
    if (typeof settingsDialog.showModal === 'function') {
      settingsDialog.showModal();
    } else {
      settingsDialog.setAttribute('open', '');
    }
  });

  settingsCancel.addEventListener('click', () => settingsDialog.close());

  // Click on the backdrop (the <dialog> element itself, not its content) closes it.
  settingsDialog.addEventListener('click', (event) => {
    if (event.target === settingsDialog) settingsDialog.close();
  });

  settingsForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const endpoint = safeBrowsingEndpointInput.value.trim();
    const settings = loadSettings();

    if (endpoint) {
      if (!/^https:\/\//i.test(endpoint)) {
        safeBrowsingEndpointInput.setCustomValidity('Endpoint must start with https://');
        safeBrowsingEndpointInput.reportValidity();
        return;
      }
      settings.workerEndpoint = endpoint;
    } else {
      delete settings.workerEndpoint;
    }

    safeBrowsingEndpointInput.setCustomValidity('');
    saveSettings(settings);
    settingsDialog.close();
  });

  // -----------------------------------------------------------------------
  // History (stored locally only)
  // -----------------------------------------------------------------------
  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  }

  function saveHistoryEntry(entry) {
    const history = loadHistory();
    history.unshift(entry);
    while (history.length > MAX_HISTORY) history.pop();
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (_) {
      // ignore
    }
    renderHistory();
  }

  function clearHistory() {
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch (_) {
      // ignore
    }
    renderHistory();
  }

  clearHistoryBtn.addEventListener('click', clearHistory);

  function renderHistory() {
    const history = loadHistory();
    recentList.textContent = '';

    if (history.length === 0) {
      recentEmpty.hidden = false;
      clearHistoryBtn.hidden = true;
      return;
    }

    recentEmpty.hidden = true;
    clearHistoryBtn.hidden = false;

    for (const entry of history) {
      const li = document.createElement('li');
      li.className = 'recent-item';

      const dot = document.createElement('span');
      dot.className = 'recent-dot verdict-' + (entry.verdict || 'info');
      li.appendChild(dot);

      const text = document.createElement('span');
      text.className = 'recent-text';
      text.textContent = entry.display;
      li.appendChild(text);

      const label = document.createElement('span');
      label.className = 'recent-label';
      label.textContent = entry.label;
      li.appendChild(label);

      recentList.appendChild(li);
    }
  }

  // -----------------------------------------------------------------------
  // Camera scanning
  // -----------------------------------------------------------------------
  startScanBtn.addEventListener('click', startScanning);

  cancelScanBtn.addEventListener('click', async () => {
    acceptingScans = false;
    await stopScanning();
    showView(viewHome);
  });

  async function startScanning() {
    homeStatus.textContent = '';
    showView(viewScanner);
    scannerStatus.textContent = 'Requesting camera access\u2026';
    acceptingScans = true;

    if (typeof Html5Qrcode === 'undefined') {
      scannerStatus.textContent = 'The QR scanning library failed to load.';
      return;
    }

    html5QrCode = new Html5Qrcode(SCANNER_ELEMENT_ID);

    const config = {
      fps: 10,
      qrbox: (viewfinderWidth, viewfinderHeight) => {
        const size = Math.floor(Math.min(viewfinderWidth, viewfinderHeight) * 0.7);
        return { width: size, height: size };
      },
      aspectRatio: 1.0
    };

    try {
      await html5QrCode.start({ facingMode: 'environment' }, config, onScanSuccess, onScanFailure);
      scannerStatus.textContent = 'Point your camera at a QR code';
    } catch (err) {
      scannerStatus.textContent = describeCameraError(err);
    }
  }

  function onScanSuccess(decodedText) {
    if (!acceptingScans) return;
    acceptingScans = false;
    stopScanning();
    processResult(decodedText);
  }

  // Called continuously while no code is found in the frame — intentionally a no-op.
  function onScanFailure(_message) {}

  async function stopScanning() {
    if (html5QrCode) {
      try {
        await html5QrCode.stop();
      } catch (_) {
        // may already be stopped
      }
      try {
        html5QrCode.clear();
      } catch (_) {
        // ignore
      }
      html5QrCode = null;
    }
  }

  function describeCameraError(err) {
    const name = (err && err.name) || '';

    if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
      return 'Camera access requires a secure (HTTPS) connection.';
    }
    if (name === 'NotAllowedError' || /permission/i.test(String(err))) {
      return 'Camera access was denied. Allow camera access for this site in your browser settings and try again.';
    }
    if (name === 'NotFoundError') {
      return 'No camera was found on this device.';
    }
    if (name === 'NotReadableError') {
      return 'The camera is already in use by another app.';
    }
    return 'Could not access the camera. You can also upload a photo of a QR code from the home screen.';
  }

  // -----------------------------------------------------------------------
  // File-based scanning
  // -----------------------------------------------------------------------
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = ''; // allow re-selecting the same file later
    if (!file) return;

    if (typeof Html5Qrcode === 'undefined') {
      homeStatus.textContent = 'The QR scanning library failed to load.';
      return;
    }

    homeStatus.textContent = 'Reading image\u2026';

    if (!fileScanner) {
      fileScanner = new Html5Qrcode(SCANNER_ELEMENT_ID);
    }

    try {
      const decodedText = await fileScanner.scanFile(file, false);
      homeStatus.textContent = '';
      processResult(decodedText);
    } catch (_) {
      homeStatus.textContent = 'No QR code was found in that image.';
    }
  });

  // -----------------------------------------------------------------------
  // Result handling
  // -----------------------------------------------------------------------
  function processResult(rawText) {
    const result = QRAnalyzer.classify(rawText);
    renderResult(result);
    saveHistoryEntry(toHistoryEntry(result));
    showView(viewResults);

    if (result.type === 'url') {
      maybeCheckSafeBrowsing(result);
    }
  }

  function typeLabel(type) {
    switch (type) {
      case 'wifi':
        return 'Wi-Fi config';
      case 'contact':
        return 'Contact card';
      case 'text':
        return 'Text';
      case 'empty':
        return 'Empty';
      default:
        return 'Unknown';
    }
  }

  function summarize(result) {
    let s;
    if (result.type === 'url') {
      s = result.url.hostname + result.url.pathname;
      if (!s.trim()) s = result.raw;
    } else {
      s = result.raw.replace(/\s+/g, ' ').trim();
    }
    if (s.length > 42) s = s.slice(0, 42) + '\u2026';
    return s || '(empty)';
  }

  function toHistoryEntry(result) {
    return {
      display: summarize(result),
      verdict: result.type === 'url' ? result.analysis.verdict : 'info',
      label: result.type === 'url' ? result.analysis.label : typeLabel(result.type)
    };
  }

  // -----------------------------------------------------------------------
  // Rendering
  // -----------------------------------------------------------------------
  function renderResult(result) {
    findingsList.textContent = '';
    safebrowsingStatus.textContent = '';
    copyFeedback.textContent = '';
    openBtn.hidden = true;
    currentOpenUrl = null;

    // Scanned content is untrusted input — always set via textContent.
    scannedContent.textContent = result.raw;

    if (result.type === 'url') {
      renderUrlResult(result);
    } else {
      renderNonUrlResult(result);
    }
  }

  function renderUrlResult(result) {
    const { analysis, url } = result;
    setVerdict(analysis.verdict, analysis.label, analysis.score);

    if (analysis.verdict === 'high') {
      verdictSub.textContent = 'This QR code shows strong signs of being unsafe.';
    } else if (analysis.verdict === 'medium') {
      verdictSub.textContent = 'A few things about this link are worth double-checking.';
    } else if (analysis.verdict === 'info') {
      verdictSub.textContent = '';
    } else {
      verdictSub.textContent = "We didn't find anything unusual about this link's structure.";
    }

    renderFindings(analysis.findings);

    const scheme = url.protocol.replace(':', '').toLowerCase();
    const dangerous = QRAnalyzer.DANGEROUS_SCHEMES.includes(scheme);

    if (!dangerous) {
      currentOpenUrl = url;
      openBtn.hidden = false;
      openBtn.textContent = ['mailto', 'tel', 'sms', 'smsto', 'geo'].includes(scheme) ? 'Open' : 'Open link';
    }
  }

  function renderNonUrlResult(result) {
    setVerdict('info', typeLabel(result.type), null);

    switch (result.type) {
      case 'wifi':
        verdictSub.textContent = 'This QR code sets up a Wi-Fi connection rather than opening a link.';
        renderFindings([
          {
            severity: 'info',
            title: 'Wi-Fi network details',
            detail:
              'This code contains a network name and password for connecting to Wi-Fi. Only join networks you recognize and trust.'
          }
        ]);
        break;
      case 'contact':
        verdictSub.textContent = 'This QR code contains contact details rather than a link.';
        renderFindings([
          {
            severity: 'info',
            title: 'Contact information',
            detail: 'This code contains a name, number, or other contact details. Make sure you recognize the source before saving it.'
          }
        ]);
        break;
      case 'text':
        verdictSub.textContent = "This QR code contains plain text \u2014 it doesn't open a website.";
        renderFindings([]);
        break;
      case 'empty':
      default:
        verdictSub.textContent = '';
        renderFindings([
          {
            severity: 'info',
            title: 'No data found',
            detail: 'This QR code does not appear to contain any readable data.'
          }
        ]);
        break;
    }
  }

  function setVerdict(verdict, label, score) {
    verdictCard.classList.remove('verdict-low', 'verdict-medium', 'verdict-high', 'verdict-info');
    verdictCard.classList.add('verdict-' + verdict);
    currentVerdict = verdict;

    verdictLabel.textContent = label;

    if (typeof score === 'number') {
      verdictScore.textContent = String(score);
      verdictRing.style.setProperty('--pct', score);
      verdictRing.classList.remove('verdict-ring-empty');
    } else {
      verdictScore.textContent = '';
      verdictRing.style.setProperty('--pct', '0');
      verdictRing.classList.add('verdict-ring-empty');
    }
  }

  function renderFindings(findings) {
    findingsList.textContent = '';

    if (findings.length === 0) {
      findingsList.appendChild(
        buildFindingItem({
          severity: 'info',
          title: 'No structural warning signs',
          detail: 'We did not detect any of the common red flags this tool checks for.'
        })
      );
      return;
    }

    for (const finding of findings) {
      findingsList.appendChild(buildFindingItem(finding));
    }
  }

  function buildFindingItem(finding) {
    const li = document.createElement('li');
    li.className = 'finding finding-' + finding.severity;

    const header = document.createElement('div');
    header.className = 'finding-header';

    const badge = document.createElement('span');
    badge.className = 'finding-badge';
    badge.textContent = SEVERITY_LABELS[finding.severity] || finding.severity;
    header.appendChild(badge);

    const title = document.createElement('h3');
    title.className = 'finding-title';
    title.textContent = finding.title;
    header.appendChild(title);

    li.appendChild(header);

    const detail = document.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = finding.detail;
    li.appendChild(detail);

    return li;
  }

  // -----------------------------------------------------------------------
  // Result actions: copy / open / scan again
  // -----------------------------------------------------------------------
  copyBtn.addEventListener('click', async () => {
    const text = scannedContent.textContent || '';
    try {
      await navigator.clipboard.writeText(text);
      copyFeedback.textContent = 'Copied to clipboard.';
    } catch (_) {
      copyFeedback.textContent = 'Could not copy automatically \u2014 select and copy the text above.';
    }
    setTimeout(() => {
      copyFeedback.textContent = '';
    }, 3000);
  });

  openBtn.addEventListener('click', () => {
    if (!currentOpenUrl) return;

    let message = 'Open this in a new tab?';
    if (currentVerdict === 'high') {
      message = 'This showed strong warning signs. Are you sure you want to open it?';
    } else if (currentVerdict === 'medium') {
      message = 'This has a few warning signs. Open it anyway?';
    }

    const target = currentOpenUrl.toString();
    if (window.confirm(message + '\n\n' + target)) {
      window.open(target, '_blank', 'noopener,noreferrer');
    }
  });

  scanAgainBtn.addEventListener('click', () => {
    startScanning();
  });

  // -----------------------------------------------------------------------
  // Optional Google Safe Browsing cross-check
  // -----------------------------------------------------------------------
  async function maybeCheckSafeBrowsing(result) {
    const settings = loadSettings();
    const endpoint = settings.workerEndpoint;
    if (!endpoint) return;

    const scheme = result.url.protocol.replace(':', '').toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') return;

    safebrowsingStatus.textContent = 'Checking Google Safe Browsing\u2026';

    try {
      const sb = await QRAnalyzer.checkSafeBrowsing(result.url.toString(), endpoint);

      if (sb.flagged) {
        safebrowsingStatus.textContent = '';
        findingsList.insertBefore(
          buildFindingItem({
            severity: 'critical',
            title: 'Flagged by Google Safe Browsing',
            detail:
              'Google\u2019s Safe Browsing service lists this link as: ' +
              sb.threatTypes.join(', ') +
              '. Treat this link as unsafe and avoid opening it.'
          }),
          findingsList.firstChild
        );
        setVerdict('high', 'High Risk', 0);
        verdictSub.textContent = 'This link is listed as dangerous by Google Safe Browsing.';
        openBtn.hidden = true;
        currentOpenUrl = null;
      } else {
        safebrowsingStatus.textContent = 'Google Safe Browsing: no known threats found for this link.';
      }
    } catch (_) {
      safebrowsingStatus.textContent = 'Google Safe Browsing check could not be completed.';
    }
  }

  // -----------------------------------------------------------------------
  // Init
  // -----------------------------------------------------------------------
  renderHistory();
})();
