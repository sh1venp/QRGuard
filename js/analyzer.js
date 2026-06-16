/**
 * analyzer.js
 *
 * Heuristic safety analysis for content decoded from a QR code.
 *
 * IMPORTANT SECURITY NOTE:
 * This module only ever READS the decoded text and computes a risk
 * assessment from it. It never executes, navigates to, or injects the
 * scanned content. Anything derived from `rawText` that ends up in the
 * UI must be rendered as text (textContent), never as HTML.
 *
 * Exposed globally as `window.QRAnalyzer`.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------------
  // Reference data
  // ---------------------------------------------------------------------

  // Schemes that should basically never appear in a "scan this to visit a
  // website" QR code. Their presence is treated as a critical red flag.
  const DANGEROUS_SCHEMES = ['javascript', 'vbscript', 'data', 'file'];

  // Schemes that point at something other than a website (phone numbers,
  // email addresses, etc). These get a lighter-touch, informational review.
  const NON_WEB_SCHEMES = ['mailto', 'tel', 'sms', 'smsto', 'geo', 'market', 'intent'];

  // Known URL shorteners. A shortener isn't inherently malicious, but it
  // hides the real destination until the link is followed.
  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bl.ink', 'lnkd.in', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'rb.gy', 'tiny.cc', 'shorte.st', 'v.gd', 'soo.gd', 'clck.ru', 's.id',
    'tr.im', 'qr.ae', 'mcaf.ee', 'rotf.lol', 'shrtco.de'
  ];

  // Top-level domains that are disproportionately used for throwaway /
  // low-cost sites, including a large share of scam and phishing pages.
  // Presence here is only a mild signal, not proof of anything.
  const WATCHLIST_TLDS = [
    'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work',
    'click', 'link', 'loan', 'download', 'review', 'country', 'kim',
    'men', 'party', 'gdn', 'icu', 'rest', 'biz'
  ];

  // File extensions in the URL path that suggest a direct file/app
  // download rather than a normal web page.
  const EXECUTABLE_EXTENSIONS = [
    '.exe', '.apk', '.msi', '.bat', '.cmd', '.scr', '.jar', '.vbs',
    '.ps1', '.dmg', '.pkg', '.deb', '.rpm', '.lnk', '.iso', '.com'
  ];

  // Words that show up frequently in phishing URLs, especially when
  // combined with a brand name elsewhere in the domain.
  const PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'billing', 'suspended', 'unlock', 'reset', 'password',
    'invoice', 'wallet', 'support'
  ];

  // Well-known brand names mapped to their legitimate domain suffixes.
  // Used to flag domains that *mention* a brand without actually
  // belonging to it (a classic phishing pattern).
  const BRAND_DOMAINS = {
    paypal: ['paypal.com', 'paypal.me'],
    google: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl', 'android.com', 'googleusercontent.com', 'gstatic.com', 'withgoogle.com'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com', 'microsoftonline.com', 'windows.com', 'azure.com', 'sharepoint.com'],
    apple: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazonaws.com', 'a2z.com', 'primevideo.com'],
    facebook: ['facebook.com', 'fb.com', 'messenger.com', 'fbcdn.net'],
    instagram: ['instagram.com', 'cdninstagram.com'],
    netflix: ['netflix.com', 'nflxext.com'],
    whatsapp: ['whatsapp.com', 'whatsapp.net'],
    linkedin: ['linkedin.com', 'licdn.com'],
    dropbox: ['dropbox.com', 'dropboxusercontent.com'],
    adobe: ['adobe.com'],
    ebay: ['ebay.com', 'ebayimg.com'],
    dhl: ['dhl.com', 'dhl.de'],
    fedex: ['fedex.com'],
    ups: ['ups.com'],
    usps: ['usps.com'],
    chase: ['chase.com'],
    wellsfargo: ['wellsfargo.com'],
    bankofamerica: ['bankofamerica.com'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    binance: ['binance.com'],
    coinbase: ['coinbase.com']
  };

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  /** True if `host` is an IPv4 dotted-quad or an IPv6 literal. */
  function isIpAddress(host) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4.test(host)) {
      return host.split('.').every((part) => Number(part) <= 255);
    }
    // URL.hostname for IPv6 comes back without brackets, e.g. "::1"
    if (host.includes(':')) {
      return /^[0-9a-fA-F:]+$/.test(host);
    }
    return false;
  }

  /** True if `host` is entirely numeric (a likely decimal-IP obfuscation). */
  function isAllDigits(host) {
    return /^\d+$/.test(host);
  }

  /**
   * Attempt to parse `text` as a URL. If it lacks a scheme but looks like
   * a bare domain (e.g. "example.com/path"), assume https.
   * Returns a URL object, or null if it doesn't look like a URL at all.
   */
  function tryParseUrl(text) {
    try {
      return new URL(text);
    } catch (_) {
      /* fall through */
    }

    // Looks like "domain.tld" or "domain.tld/something", with no spaces.
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(text)) {
      try {
        return new URL('https://' + text);
      } catch (_) {
        return null;
      }
    }
    return null;
  }

  function addFinding(findings, severity, title, detail) {
    findings.push({ severity, title, detail });
  }

  const SEVERITY_WEIGHT = {
    critical: 60,
    high: 25,
    medium: 12,
    low: 6,
    info: 0
  };

  // ---------------------------------------------------------------------
  // Classification of arbitrary QR payloads
  // ---------------------------------------------------------------------

  /**
   * Classify raw decoded QR text into a content type and (for URLs) run
   * the safety analysis.
   *
   * @param {string} rawText - exactly what the QR code decoded to.
   * @returns {object} classification result, see inline comments below.
   */
  function classify(rawText) {
    const trimmed = (rawText || '').trim();

    if (trimmed.length === 0) {
      return { type: 'empty', raw: rawText };
    }

    // Wi-Fi network configuration: WIFI:S:<ssid>;T:<auth>;P:<password>;;
    if (/^WIFI:/i.test(trimmed)) {
      return { type: 'wifi', raw: trimmed };
    }

    // Contact card formats.
    if (/^(BEGIN:VCARD|MECARD:)/i.test(trimmed)) {
      return { type: 'contact', raw: trimmed };
    }

    const url = tryParseUrl(trimmed);
    if (url) {
      return { type: 'url', raw: trimmed, url, analysis: analyzeUrl(url, trimmed) };
    }

    return { type: 'text', raw: trimmed };
  }

  // ---------------------------------------------------------------------
  // URL heuristic analysis
  // ---------------------------------------------------------------------

  /**
   * Run heuristic checks against a parsed URL and produce a score,
   * a risk verdict, and a list of human-readable findings.
   */
  function analyzeUrl(url, rawText) {
    const findings = [];
    const scheme = url.protocol.replace(':', '').toLowerCase();
    const hostname = url.hostname.toLowerCase();

    // --- Non-web schemes get a short, separate review -------------------
    if (NON_WEB_SCHEMES.includes(scheme)) {
      addFinding(
        findings,
        'info',
        'Not a website link',
        `This QR code contains a "${scheme}:" link, which opens an app (such as your phone dialer, messages, or maps) instead of a website. ` +
          'These can still be used to pre-fill a message or call a premium-rate number, so only proceed if you recognize the destination.'
      );
      return finalize(findings, { nonWeb: true });
    }

    // --- Outright dangerous schemes -------------------------------------
    if (DANGEROUS_SCHEMES.includes(scheme)) {
      addFinding(
        findings,
        'critical',
        'Dangerous link type',
        `This QR code uses a "${scheme}:" payload, which can run code or embed data directly in the browser rather than linking to a normal web page. ` +
          'Legitimate QR codes practically never use this. Do not open it.'
      );
      return finalize(findings, {});
    }

    // From here on we're dealing with http/https/ftp-style URLs.

    // 1. Plaintext HTTP
    if (scheme === 'http') {
      addFinding(
        findings,
        'medium',
        'Unencrypted connection (HTTP)',
        'This link uses HTTP rather than HTTPS, so any information exchanged with the site is not encrypted in transit and could be intercepted.'
      );
    }

    // 2. Unusual scheme (not http/https/ftp)
    if (!['http', 'https', 'ftp'].includes(scheme)) {
      addFinding(
        findings,
        'medium',
        `Unusual link type ("${scheme}:")`,
        `This link uses the "${scheme}:" scheme, which is uncommon for QR codes meant to open a website. Make sure you recognize the app this would open.`
      );
    }

    // 3. Credentials embedded in the URL ("@" trick)
    if (url.username || url.password) {
      addFinding(
        findings,
        'critical',
        '"@" used to disguise the real destination',
        'The link includes a username/password section before the "@" symbol. ' +
          'Browsers ignore everything before the final "@", so attackers use this to make a link look like it points to a trusted site (e.g. ' +
          '"https://your-bank.com@evil.example") when it actually goes somewhere else entirely.'
      );
    }

    // 4. IP address or numeric host instead of a domain name
    if (isIpAddress(hostname)) {
      addFinding(
        findings,
        'high',
        'Raw IP address instead of a domain name',
        `The link points directly to the address "${hostname}" rather than a named website. Legitimate businesses almost always use a domain name, so this is unusual.`
      );
    } else if (isAllDigits(hostname)) {
      addFinding(
        findings,
        'high',
        'Numeric host name',
        `The host "${hostname}" is purely numeric. This can be a way of writing an IP address in decimal form to make a destination harder to recognize.`
      );
    }

    // 5. Punycode / internationalized domain names
    if (hostname.includes('xn--')) {
      addFinding(
        findings,
        'high',
        'Internationalized domain name (punycode)',
        'The domain is encoded using punycode, which is how browsers represent non-Latin characters. ' +
          'This is sometimes legitimate, but it is also how "lookalike" domains are built using letters from other alphabets that resemble familiar brand names.'
      );
    }

    // 6. Excessive subdomain depth
    const labels = hostname.split('.').filter(Boolean);
    if (labels.length > 4) {
      addFinding(
        findings,
        'medium',
        'Unusually deep subdomain structure',
        `The host name "${hostname}" has ${labels.length} parts. Long chains of subdomains are sometimes used to push the real domain out of view on a small mobile screen ` +
          '(e.g. "paypal.com.security-check.example.net").'
      );
    }

    // 7. URL shorteners
    const bareHost = hostname.replace(/^www\./, '');
    if (URL_SHORTENERS.includes(bareHost)) {
      addFinding(
        findings,
        'low',
        'Shortened link',
        `"${bareHost}" is a link-shortening service. The real destination is hidden until the link is opened, which is commonly used to disguise both legitimate and malicious links alike.`
      );
    }

    // 8. Watchlist top-level domains
    const tld = labels.length ? labels[labels.length - 1] : '';
    if (WATCHLIST_TLDS.includes(tld)) {
      addFinding(
        findings,
        'low',
        `Less common domain ending (".${tld}")`,
        `Domains ending in ".${tld}" are inexpensive to register and are used disproportionately often for short-lived scam and phishing sites. ` +
          'This alone does not mean the site is unsafe, but it is a reason to be more careful.'
      );
    }

    // 9. Brand-name impersonation pattern
    const brandFinding = checkBrandImpersonation(hostname);
    if (brandFinding) {
      addFinding(findings, brandFinding.severity, brandFinding.title, brandFinding.detail);
    }

    // 10. Excessive hyphens in the host name (skip punycode domains, where
    // hyphens are an artifact of the "xn--" encoding itself).
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3 && !hostname.includes('xn--')) {
      addFinding(
        findings,
        'low',
        'Many hyphens in the domain',
        `The domain "${hostname}" contains ${hyphenCount} hyphens. Strings of hyphenated words in a domain are a common pattern in disposable phishing domains.`
      );
    }

    // 11. Phishing-style keywords in the host name
    const matchedKeywords = PHISHING_KEYWORDS.filter((kw) => hostname.includes(kw));
    if (matchedKeywords.length > 0 && !brandFinding) {
      addFinding(
        findings,
        'low',
        'Account/security-themed wording in the domain',
        `The domain contains the word${matchedKeywords.length > 1 ? 's' : ''} "${matchedKeywords.join('", "')}". ` +
          'Words like these are common in both legitimate sites and in phishing pages designed to create urgency around your account.'
      );
    }

    // 12. Executable / package file extensions in the path
    const path = url.pathname.toLowerCase();
    const matchedExt = EXECUTABLE_EXTENSIONS.find((ext) => path.endsWith(ext));
    if (matchedExt) {
      addFinding(
        findings,
        'high',
        `Direct download of a "${matchedExt}" file`,
        `The link points to a "${matchedExt}" file. QR codes that lead straight to an installable program or app are a common malware-distribution technique, especially outside official app stores.`
      );
    }

    // 13. Very long URL
    const fullLength = url.toString().length;
    if (fullLength > 120) {
      addFinding(
        findings,
        'low',
        'Very long link',
        `This link is ${fullLength} characters long. Unusually long links are sometimes used to bury the real domain or to encode tracking/redirect data that hides the final destination.`
      );
    }

    // 14. Non-standard port
    if (url.port && !['80', '443', ''].includes(url.port)) {
      addFinding(
        findings,
        'low',
        `Non-standard port (${url.port})`,
        `The link explicitly connects on port ${url.port} instead of the standard web ports. This is sometimes used by self-hosted services, but it's also used to run services that wouldn't otherwise be reachable.`
      );
    }

    return finalize(findings, {});
  }

  /**
   * Check whether a hostname mentions a well-known brand without actually
   * being that brand's domain.
   */
  function checkBrandImpersonation(hostname) {
    for (const [brand, legitDomains] of Object.entries(BRAND_DOMAINS)) {
      if (!hostname.includes(brand)) continue;

      const isLegit = legitDomains.some(
        (d) => hostname === d || hostname.endsWith('.' + d)
      );
      if (isLegit) continue;

      return {
        severity: 'high',
        title: `Mentions "${brand}" but isn't ${brand}'s site`,
        detail:
          `The domain "${hostname}" contains the name "${brand}", but does not match any of ${brand}'s known domains. ` +
          'This is a common pattern in phishing links that imitate well-known brands to appear trustworthy. ' +
          '(This check is pattern-based and can occasionally flag legitimate sites too — if you recognize and trust this exact domain, you can disregard it.)'
      };
    }
    return null;
  }

  /**
   * Turn a list of findings into a final score + verdict.
   */
  function finalize(findings, opts) {
    if (opts.nonWeb) {
      return { score: null, verdict: 'info', label: 'Not a Website Link', findings };
    }

    let score = 100;
    for (const f of findings) {
      score -= SEVERITY_WEIGHT[f.severity] || 0;
    }
    score = Math.max(0, Math.min(100, score));

    const hasCritical = findings.some((f) => f.severity === 'critical');

    let verdict;
    let label;
    if (hasCritical || score < 45) {
      verdict = 'high';
      label = 'High Risk';
    } else if (score < 80) {
      verdict = 'medium';
      label = 'Use Caution';
    } else {
      verdict = 'low';
      label = 'Likely Safe';
    }

    return { score, verdict, label, findings };
  }

  // ---------------------------------------------------------------------
  // Optional: Google Safe Browsing cross-check
  // ---------------------------------------------------------------------

  /**
   * Ask the Safe Browsing proxy Worker whether a URL is flagged.
   * The Worker holds the real Google API key server-side; the browser
   * never sees it. Throws on network/HTTP errors so the caller can decide
   * how to surface that.
   *
   * @param {string} targetUrl - the full URL to check.
   * @param {string} workerEndpoint - the Cloudflare Worker URL, e.g.
   *   "https://qr-sentry-safebrowsing-proxy.YOUR-SUBDOMAIN.workers.dev".
   */
  async function checkSafeBrowsing(targetUrl, workerEndpoint) {
    const response = await fetch(workerEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      let detail = '';
      try {
        const body = await response.json();
        detail = body && body.error ? body.error : '';
      } catch (_) {
        // ignore
      }
      throw new Error('Safe Browsing proxy request failed (HTTP ' + response.status + ')' + (detail ? ': ' + detail : ''));
    }

    const data = await response.json();
    return {
      flagged: Boolean(data.flagged),
      threatTypes: Array.isArray(data.threatTypes) ? data.threatTypes : []
    };
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------

  window.QRAnalyzer = {
    classify,
    checkSafeBrowsing,
    DANGEROUS_SCHEMES,
    NON_WEB_SCHEMES
  };
})();
