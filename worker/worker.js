/**
 * Cloudflare Worker: Safe Browsing proxy + redirect resolver
 *
 * Purpose: lets the QR Sentry frontend (1) check a URL against Google Safe
 * Browsing and (2) follow shortener redirect chains (bit.ly, tinyurl, etc.)
 * to find the real destination — all WITHOUT ever exposing the Safe
 * Browsing API key to the browser, and without letting the browser itself
 * make cross-origin requests that a malicious redirect could abuse.
 *
 * Routes:
 *   POST /safebrowsing   { url }  -> { flagged, threatTypes }
 *   POST /resolve        { url }  -> { finalUrl, hops, hopCount, truncated }
 *
 * Security properties:
 *  - CORS is locked to an explicit allowlist of origins (your GitHub Pages
 *    URL). No wildcard "*".
 *  - Only POST is accepted, only a single well-formed `url` field is read
 *    from the body, and it is validated as http/https before use.
 *  - /resolve actively defends against SSRF: before connecting to ANY hop
 *    (including the first), the hostname is resolved and checked against
 *    private/loopback/link-local/reserved IP ranges, and rejected if it
 *    matches. This stops a malicious shortener from using this Worker to
 *    probe Cloudflare's internal network or cloud metadata endpoints.
 *  - Redirect chains are capped (MAX_REDIRECTS) and time-limited, so a
 *    pathological or infinite redirect chain can't tie up the Worker.
 *  - The Worker never echoes back arbitrary response bodies from
 *    upstream — only the resolved URL string and HTTP status per hop.
 *  - Basic per-IP rate limiting (in-memory, best-effort) to slow down abuse
 *    of your quota; Cloudflare's own DDoS protection sits in front of this
 *    regardless.
 *  - The API key is never logged.
 */

// ---- Configuration ---------------------------------------------------

// Add every origin that's allowed to call this Worker. Update this when
// you know your final GitHub Pages URL (and a custom domain, if any).
const ALLOWED_ORIGINS = [
  'https://sh1venp.github.io',
  'http://localhost:8080',
  'http://127.0.0.1:8080'
];

const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const MAX_REDIRECTS = 10;
const FETCH_TIMEOUT_MS = 6000;

// Very small in-memory rate limiter. Resets whenever the Worker's
// execution context recycles (which Cloudflare does periodically), so
// this is a speed bump against casual abuse, not a hard guarantee.
// For a stricter limit, see the README section on Cloudflare Rate Limiting
// rules (also free, configured in the dashboard, no code needed).
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 20;
const rateLimitMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { windowStart: now, count: 1 });
    return false;
  }

  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
}

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin);
  return {
    'Access-Control-Allow-Origin': allowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin'
  };
}

function jsonResponse(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin)
    }
  });
}

function isHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------
// SSRF protection: reject hostnames/IPs that point at private, loopback,
// link-local, or otherwise non-public address space. Cloud metadata
// services (AWS/GCP/Azure all use 169.254.169.254) live in link-local
// space, so blocking that range specifically matters.
// ---------------------------------------------------------------------

function ipv4ToInt(parts) {
  return (
    (parseInt(parts[0], 10) << 24) +
    (parseInt(parts[1], 10) << 16) +
    (parseInt(parts[2], 10) << 8) +
    parseInt(parts[3], 10)
  );
}

function isPrivateIpv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return false;

  const ip = ipv4ToInt(parts);
  const inRange = (base, maskBits) => {
    const mask = maskBits === 0 ? 0 : (-1 << (32 - maskBits)) >>> 0;
    return (ip & mask) === (ipv4ToInt(base) & mask);
  };

  return (
    inRange([10, 0, 0, 0], 8) || // 10.0.0.0/8
    inRange([172, 16, 0, 0], 12) || // 172.16.0.0/12
    inRange([192, 168, 0, 0], 16) || // 192.168.0.0/16
    inRange([127, 0, 0, 0], 8) || // loopback
    inRange([169, 254, 0, 0], 16) || // link-local incl. cloud metadata
    inRange([0, 0, 0, 0], 8) || // "this network"
    inRange([100, 64, 0, 0], 10) || // shared address space (CGNAT)
    inRange([192, 0, 0, 0], 24) || // IETF protocol assignments
    inRange([198, 18, 0, 0], 15) || // benchmarking
    inRange([224, 0, 0, 0], 4) // multicast
  );
}

function isPrivateIpv6(host) {
  const h = host.toLowerCase();
  return (
    h === '::1' || // loopback
    h === '::' ||
    h.startsWith('fe80:') || // link-local
    h.startsWith('fc') || // unique local fc00::/7
    h.startsWith('fd') ||
    h.startsWith('::ffff:127.') || // IPv4-mapped loopback
    h.startsWith('::ffff:10.') ||
    h.startsWith('::ffff:169.254.')
  );
}

/**
 * Resolve a hostname to its IP addresses using DNS-over-HTTPS (Cloudflare's
 * own 1.1.1.1 resolver) so we can inspect the actual IP before connecting,
 * rather than trusting the hostname alone (which doesn't stop DNS rebinding
 * to a private address).
 */
async function resolveHostIps(hostname) {
  const lookupTypes = ['A', 'AAAA'];
  const ips = [];

  for (const type of lookupTypes) {
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' } }
      );
      if (!res.ok) continue;
      const data = await res.json();
      if (Array.isArray(data.Answer)) {
        for (const ans of data.Answer) {
          if (ans && typeof ans.data === 'string') ips.push(ans.data);
        }
      }
    } catch (_) {
      // DNS lookup failure is treated as "couldn't verify" — caller decides.
    }
  }

  return ips;
}

/**
 * Returns true if `hostname` is safe to connect to: it must resolve to at
 * least one IP, and none of its IPs may fall in private/reserved space.
 */
async function isSafeToFetch(hostname) {
  // Reject if the hostname itself is a literal private/loopback IP.
  if (isPrivateIpv4(hostname) || isPrivateIpv6(hostname)) return false;
  if (hostname === 'localhost') return false;

  const ips = await resolveHostIps(hostname);
  if (ips.length === 0) {
    // Could not resolve at all — fail closed.
    return false;
  }

  return ips.every((ip) => !isPrivateIpv4(ip) && !isPrivateIpv6(ip));
}

/**
 * Some link shorteners (TinyURL among them, depending on configuration)
 * serve an HTML interstitial page with a 200 status instead of an HTTP
 * 3xx redirect — the actual destination is embedded as a meta-refresh tag
 * or a small inline script. This is a best-effort fallback to extract that
 * destination when no Location header was present. Returns null if no
 * redirect-like pattern is found, in which case the page genuinely IS the
 * final destination.
 */
function extractHtmlRedirectTarget(html, baseUrl) {
  if (!html || typeof html !== 'string') return null;

  // <meta http-equiv="refresh" content="0;url=https://example.com">
  const metaMatch = html.match(
    /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?[^"'>]*url=([^"'>\s]+)/i
  );
  if (metaMatch) {
    try {
      return new URL(metaMatch[1], baseUrl).toString();
    } catch (_) {
      /* fall through to other patterns */
    }
  }

  // window.location = "..." / window.location.href = "..." / location.replace("...")
  const jsMatch = html.match(
    /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.replace\(\s*["']([^"']+)["']\s*\)/i
  );
  if (jsMatch) {
    const target = jsMatch[1] || jsMatch[2];
    try {
      return new URL(target, baseUrl).toString();
    } catch (_) {
      /* fall through */
    }
  }

  return null;
}

/**
 * Follow redirects from `startUrl` one hop at a time, validating each
 * hop's destination before connecting. Returns the chain of URLs visited
 * and the final resolved URL (or as far as it safely got).
 */
async function resolveRedirects(startUrl) {
  const hops = [];
  let current = startUrl;
  let truncated = false;

  for (let i = 0; i < MAX_REDIRECTS; i++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch (_) {
      break;
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      // A redirect pointed somewhere non-web (e.g. a custom app scheme).
      // Stop here; report what we have.
      break;
    }

    const safe = await isSafeToFetch(parsed.hostname);
    if (!safe) {
      hops.push({ url: current, status: null, blocked: true });
      truncated = true;
      break;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    let response;
    try {
      response = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        }
      });
    } catch (_) {
      hops.push({ url: current, status: null, blocked: false, error: true });
      truncated = true;
      break;
    } finally {
      clearTimeout(timeout);
    }

    const status = response.status;
    const isRedirect = status >= 300 && status < 400;
    const headerLocation = response.headers.get('Location');

    if (isRedirect && headerLocation) {
      hops.push({ url: current, status });
      try {
        current = new URL(headerLocation, current).toString();
        continue;
      } catch (_) {
        truncated = true;
        break;
      }
    }

    // No HTTP-level redirect. Check whether this is an HTML interstitial
    // with a meta-refresh or JS-based redirect instead — but only bother
    // reading the body for plausible HTML responses, and cap how much we
    // read so a huge page can't stall the Worker.
    const contentType = response.headers.get('Content-Type') || '';
    let htmlTarget = null;

    if (status === 200 && contentType.includes('html')) {
      try {
        const reader = response.body.getReader();
        let received = '';
        const MAX_BYTES = 50_000; // interstitial pages are tiny; real content isn't needed
        let bytesRead = 0;
        const decoder = new TextDecoder();

        while (bytesRead < MAX_BYTES) {
          const { done, value } = await reader.read();
          if (done) break;
          bytesRead += value.length;
          received += decoder.decode(value, { stream: true });
        }
        try {
          await reader.cancel();
        } catch (_) {
          /* ignore */
        }

        htmlTarget = extractHtmlRedirectTarget(received, current);
      } catch (_) {
        // Body read failed — treat as "no redirect found", not an error.
      }
    }

    hops.push({ url: current, status });

    if (!htmlTarget || htmlTarget === current) {
      // Genuinely the final destination.
      return { finalUrl: current, hops, hopCount: hops.length, truncated: false };
    }

    current = htmlTarget;
  }

  // Either hit MAX_REDIRECTS, or broke out early above.
  const last = hops.length ? hops[hops.length - 1].url : startUrl;
  return { finalUrl: last, hops, hopCount: hops.length, truncated: true };
}

// ---------------------------------------------------------------------
// Safe Browsing lookup (unchanged behavior, factored into a function)
// ---------------------------------------------------------------------

async function lookupSafeBrowsing(targetUrl, apiKey) {
  const body = {
    client: { clientId: 'qr-sentry', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: targetUrl }]
    }
  };

  const response = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    throw new Error('upstream-error');
  }

  const data = await response.json();
  const matches = Array.isArray(data.matches) ? data.matches : [];

  if (matches.length === 0) {
    return { flagged: false, threatTypes: [] };
  }

  const threatTypes = [...new Set(matches.map((m) => m.threatType).filter(Boolean))];
  return { flagged: true, threatTypes };
}

// ---------------------------------------------------------------------
// Request handlers
// ---------------------------------------------------------------------

async function handleSafeBrowsing(targetUrl, env, origin) {
  const apiKey = env.SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: 'Service temporarily unavailable' }, 503, origin);
  }

  try {
    const result = await lookupSafeBrowsing(targetUrl, apiKey);
    return jsonResponse(result, 200, origin);
  } catch (_) {
    return jsonResponse({ error: 'Upstream Safe Browsing error' }, 502, origin);
  }
}

async function handleResolve(targetUrl, origin) {
  try {
    const result = await resolveRedirects(targetUrl);
    // Strip internal-only fields before returning; keep the response shape
    // small and predictable for the frontend.
    const hops = result.hops.map((h) => ({ url: h.url, status: h.status }));
    return jsonResponse(
      { finalUrl: result.finalUrl, hops, hopCount: result.hopCount, truncated: result.truncated },
      200,
      origin
    );
  } catch (_) {
    return jsonResponse({ error: 'Could not resolve redirects' }, 502, origin);
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405, origin);
    }

    if (!ALLOWED_ORIGINS.includes(origin)) {
      return jsonResponse({ error: 'Origin not allowed' }, 403, origin);
    }

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(clientIp)) {
      return jsonResponse({ error: 'Rate limit exceeded, try again shortly' }, 429, origin);
    }

    let payload;
    try {
      payload = await request.json();
    } catch (_) {
      return jsonResponse({ error: 'Invalid JSON body' }, 400, origin);
    }

    const targetUrl = payload && typeof payload.url === 'string' ? payload.url : null;
    if (!targetUrl || !isHttpUrl(targetUrl)) {
      return jsonResponse({ error: 'A valid http(s) "url" field is required' }, 400, origin);
    }

    if (url.pathname === '/resolve') {
      return handleResolve(targetUrl, origin);
    }

    // Default / legacy route: Safe Browsing lookup.
    return handleSafeBrowsing(targetUrl, env, origin);
  }
};
