/**
 * Cloudflare Worker: Safe Browsing proxy
 *
 * Purpose: lets the QR Sentry frontend check a URL against Google Safe
 * Browsing WITHOUT ever exposing the Safe Browsing API key to the browser.
 * The key lives only as a Worker secret (server-side environment variable),
 * never in any JS shipped to the client.
 *
 * Security properties:
 *  - CORS is locked to an explicit allowlist of origins (your GitHub Pages
 *    URL). No wildcard "*".
 *  - Only POST is accepted, only a single well-formed `url` field is read
 *    from the body, and it is validated as http/https before use.
 *  - The Worker never echoes back arbitrary user input into responses
 *    beyond the boolean "flagged" result and threat type names from
 *    Google's own response.
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

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

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

    const apiKey = env.SAFE_BROWSING_API_KEY;
    if (!apiKey) {
      // Misconfiguration on the server side — don't leak details to the client.
      return jsonResponse({ error: 'Service temporarily unavailable' }, 503, origin);
    }

    const sbRequestBody = {
      client: { clientId: 'qr-sentry', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: targetUrl }]
      }
    };

    let sbResponse;
    try {
      sbResponse = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sbRequestBody)
      });
    } catch (_) {
      return jsonResponse({ error: 'Upstream request failed' }, 502, origin);
    }

    if (!sbResponse.ok) {
      // Don't forward upstream error bodies verbatim (they could contain
      // the key in some edge cases, or just be unnecessarily verbose).
      return jsonResponse({ error: 'Upstream Safe Browsing error' }, 502, origin);
    }

    let sbData;
    try {
      sbData = await sbResponse.json();
    } catch (_) {
      return jsonResponse({ error: 'Upstream returned malformed data' }, 502, origin);
    }

    const matches = Array.isArray(sbData.matches) ? sbData.matches : [];
    if (matches.length === 0) {
      return jsonResponse({ flagged: false, threatTypes: [] }, 200, origin);
    }

    const threatTypes = [...new Set(matches.map((m) => m.threatType).filter(Boolean))];
    return jsonResponse({ flagged: true, threatTypes }, 200, origin);
  }
};
