# QR Sentry

A mobile-friendly web app that scans a QR code with your camera and analyzes
the embedded link for common phishing and malware warning signs &mdash;
before you open it.

**Live demo:** deploy via GitHub Pages (see below), or open `index.html`
locally / via a static server.

## How it works

1. You scan a QR code (camera or uploaded photo).
2. The decoded text is parsed and checked against a set of heuristics:
   dangerous schemes (`javascript:`, `data:`), credential-in-URL tricks,
   raw IP addresses, punycode/lookalike domains, brand-impersonation
   patterns, URL shorteners, risky TLDs, executable file downloads, and
   more.
3. You get a 0&ndash;100 safety score, a verdict (Likely Safe / Use Caution /
   High Risk), and a plain-English explanation of every finding.
4. Optionally, you can add a free Google Safe Browsing API key in Settings
   to cross-check the link against Google's database of known-malicious
   sites.

All analysis runs **entirely client-side**. Nothing is sent anywhere
unless you've added a Safe Browsing key, in which case only the scanned
URL (not your activity or identity) is sent to Google's API.

## Tech stack

- Plain HTML/CSS/JS, no build step, no framework.
- [`html5-qrcode`](https://github.com/mebjas/html5-qrcode) for camera/image
  QR decoding, vendored locally in `vendor/` (not loaded from a CDN).
- Optional: [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/v4/lookup-api) (free tier).

## Running locally

Just serve the folder with any static file server, e.g.:

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080`. Camera access requires either
`localhost` or HTTPS &mdash; it will not work over plain `http://` on a
non-localhost address.

## Deploying to GitHub Pages

1. Push this repository to GitHub.
2. In the repo, go to **Settings &rarr; Pages**.
3. Under "Build and deployment", set **Source** to "Deploy from a branch",
   choose your default branch and the `/ (root)` folder.
4. Save. GitHub will give you a URL like
   `https://<username>.github.io/<repo>/`. GitHub Pages is served over
   HTTPS automatically, so camera access will work on mobile.

## Setting up the optional Safe Browsing check

This step is optional &mdash; the heuristic analysis works fully without it.

Google Safe Browsing API keys cannot be safely embedded in client-side
JavaScript: anyone can view-source a static site and copy the key out,
regardless of "referrer restrictions" (those only constrain browser
requests, not someone calling the API directly with the stolen key). So
this project proxies the request through a small Cloudflare Worker that
holds the real key server-side. The browser only ever talks to the
Worker, never to Google directly.

### 1. Get a Safe Browsing API key

1. Create a Google Cloud project (free) at
   [console.cloud.google.com](https://console.cloud.google.com/).
2. Enable the **Safe Browsing API** for that project.
3. Create an API key under **APIs & Services &rarr; Credentials**.
4. Restrict it: under "API restrictions", limit the key to the Safe
   Browsing API only. (Skip referrer restrictions here &mdash; the Worker
   calls Google server-to-server, so there's no browser referrer to
   restrict against; the key never reaches a browser at all.)

### 2. Deploy the Worker

The Worker code lives in `worker/`.

```bash
cd worker
npm install -g wrangler   # Cloudflare's CLI, free
wrangler login
wrangler secret put SAFE_BROWSING_API_KEY   # paste your key when prompted
wrangler deploy
```

This prints a URL like `https://qr-sentry-safebrowsing-proxy.<your-subdomain>.workers.dev`.
That's your proxy endpoint &mdash; it's fine for this to be public; it
forwards requests but never reveals the key.

### 3. Lock the Worker down to your site

Open `worker/worker.js` and edit `ALLOWED_ORIGINS` to include your actual
GitHub Pages URL:

```js
const ALLOWED_ORIGINS = [
  'https://your-username.github.io',
  'http://localhost:8080'
];
```

Redeploy with `wrangler deploy`. Now the Worker rejects any request whose
`Origin` header isn't on that list, so other sites can't piggyback on
your Worker (and therefore your Google quota) even though its URL is
public.

### 4. Point the app at your Worker

Open the app, tap the gear icon, paste in your Worker URL
(`https://....workers.dev`), and save. It's stored only in this browser's
`localStorage` &mdash; it's just a URL, not a secret, so there's nothing
sensitive to protect here.

### Notes on the free tier

- Cloudflare Workers: 100,000 requests/day free, no credit card required.
- Safe Browsing API: a generous free quota (check current limits in the
  Google Cloud Console, as they can change).
- The Worker includes a basic in-memory rate limit (20 requests/min per
  IP) as a speed bump against abuse. For a stronger guarantee, configure
  a free [Cloudflare Rate Limiting rule](https://developers.cloudflare.com/waf/rate-limiting-rules/)
  in the dashboard &mdash; no code changes needed.

## Security notes

- **Strict Content-Security-Policy**: scripts only load from the app
  itself (`script-src 'self'`); nothing is loaded from third-party CDNs
  at runtime. The QR-decoding library is vendored into `vendor/` instead
  of pulled from a CDN, so there's no supply-chain risk from a compromised
  external script host.
- **No `innerHTML` of untrusted data**: text decoded from a QR code is
  attacker-controlled by definition. It is only ever written to the page
  via `textContent`, never parsed as HTML, so a malicious QR code cannot
  inject scripts or markup into the page.
- **API key never reaches the browser**: the optional Safe Browsing check
  goes through a Cloudflare Worker that holds the real Google API key as
  a server-side secret. The browser only ever sees the Worker's public
  URL, which is safe to expose. The Worker also checks the request's
  `Origin` header against an allowlist, so other sites can't use it to
  burn through your quota.
- **Links are never auto-opened**: even a link judged "Likely Safe" still
  requires an explicit tap on "Open" plus a confirmation dialog showing
  the real destination. `javascript:`, `data:`, `vbscript:`, and `file:`
  payloads are never offered as openable at all.
- **No tracking, no server**: there's no backend. The only outbound
  network call is the optional, user-initiated Safe Browsing check.
- **Local storage only**: scan history and your Worker URL preference
  live in `localStorage` on your device and are never transmitted
  anywhere except to your own Worker when a Safe Browsing check runs.

## Limitations (read before relying on this)

This is a heuristic prototype, not a guarantee. It can:

- Flag legitimate sites that happen to match a pattern (e.g. a site that
  legitimately uses a hyphenated domain or a shortener).
- Miss malicious links that don't match any known pattern, including
  freshly registered, well-disguised phishing domains using mainstream
  TLDs and no embedded brand name.

Treat the score as a prompt to think twice, not as a verdict to blindly
trust. The Safe Browsing cross-check (if enabled) adds a real, regularly
updated threat database, but no single tool catches everything.

## License

MIT &mdash; do whatever you like with this.
