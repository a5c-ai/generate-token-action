#!/usr/bin/env node
// Simple client that calls the a5c endpoint to create a GitHub App installation token
// Usage: node scripts/call-a5c-app-installation-token.js --base https://your.app --owner o --repo r --run 123 --app 456 [--insecure]
//
// Security notes:
// - TLS verification is ON by default.
// - For local/self-signed testing you may use --insecure (or env A5C_INSECURE=true / A5C_ALLOW_INSECURE_TLS=1),
//   which disables TLS verification ONLY for this request and ONLY when base is non‑production.
// - Insecure mode is refused when base host is production.

const args = require('node:process').argv.slice(2);

const https = require('https');
const http = require('http');
const { isLocalHost, isProdHost, toHost } = require('./shared/host-env');

const opts = {};
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  const n = (k) => (i + 1 < args.length ? args[++i] : undefined);
  if (a === '--base') opts.base = n('base');
  else if (a === '--owner') opts.owner = n('owner');
  else if (a === '--repo') opts.repo = n('repo');
  else if (a === '--run' || a === '--run_id') opts.run_id = n('run');
  else if (a === '--app' || a === '--app_id') opts.app_id = n('app');
  else if (a === '--insecure') opts.insecure = true;
}

async function main() {
  // Default to the production app URL for safer behavior when used ad-hoc.
  const base = opts.base || process.env.A5C_BASE_URL || 'https://app.a5c.ai';
  const owner = opts.owner || process.env.A5C_OWNER;
  const repo = opts.repo || process.env.A5C_REPO;
  const run_id = opts.run_id || process.env.GITHUB_RUN_ID;
  const app_id =
    opts.app_id ||
    process.env.AUTH_GITHUB_APP_ID ||
    process.env.A5C_GITHUB_APP_ID ||
    process.env.GITHUB_APP_ID;
  const github_token =
    process.env.GITHUB_TOKEN || process.env.ACTIONS_RUNTIME_TOKEN;

  const val = (s) =>
    String(s || '')
      .trim()
      .toLowerCase();
  const allowInsecureEnv =
    val(process.env.A5C_INSECURE) === 'true' ||
    ['1', 'true', 'yes'].includes(val(process.env.A5C_ALLOW_INSECURE_TLS)) ||
    ['1', 'true', 'yes'].includes(
      val(process.env.A5C_INSECURE_SKIP_TLS_VERIFY),
    );
  const insecureRequested = Boolean(opts.insecure || allowInsecureEnv);

  if (!owner || !repo || !run_id || !app_id) {
    console.error(
      'Missing required params. Provide --owner, --repo, --run, --app',
    );
    process.exit(2);
  }
  if (!github_token) {
    console.error('Missing GITHUB_TOKEN in env for authentication');
    process.exit(2);
  }

  // Security guardrails and per-request TLS control
  let isHttps = false;
  let isHttp = false;
  let host = '';
  let local = false;
  try {
    const u = new URL(base);
    isHttps = u.protocol === 'https:';
    isHttp = u.protocol === 'http:';
    host = toHost(base);
    local = isLocalHost(host);
  } catch {}
  // Warn when calling over plain HTTP, which is insecure; allow localhost without extra verbiage
  const suppressHttpWarn = ['1', 'true', 'yes'].includes(
    val(process.env.A5C_SUPPRESS_HTTP_WARNING),
  );
  if (isHttp && !suppressHttpWarn) {
    if (local) {
      console.error(
        `Warning: using insecure HTTP base URL (${base}). This is acceptable for local development only.`,
      );
    } else {
      console.error(
        `Warning: using insecure HTTP base URL (${base}). Prefer HTTPS in non-local environments.`,
      );
    }
  }

  // Refuse implicit global TLS bypass against non-local HTTPS endpoints
  const insecureEnv =
    String(process.env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0';
  if (isHttps && !local && insecureEnv && !insecureRequested) {
    console.error(
      'Refusing to call HTTPS endpoint with TLS verification disabled via NODE_TLS_REJECT_UNAUTHORIZED=0.',
    );
    console.error(
      'Remove NODE_TLS_REJECT_UNAUTHORIZED=0 or pass --insecure (ONLY for non-production, self-signed testing).',
    );
    process.exit(3);
  }

  // Refuse insecure mode on production base
  if (insecureRequested && isHttps && isProdHost(host)) {
    console.error(`Refusing --insecure for production host: ${host}`);
    process.exit(4);
  }
  if (insecureRequested) {
    console.warn(
      'WARNING: --insecure mode enabled. TLS certificate verification will be disabled for this request.',
    );
  }

  const url = `${base.replace(/\/$/, '')}/api/github/app/token`;

  // Make the request with per-call TLS control when needed
  const doRequest = () =>
    new Promise((resolve, reject) => {
      try {
        const u = new URL(url);
        const bodyStr = JSON.stringify({ owner, repo:repo.split("/")[repo.split("/").length-1], run_id, app_id });
        const headers = {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(bodyStr),
          authorization: `Bearer ${github_token}`,
        };
        const isHttpsReq = u.protocol === 'https:';
        const agent =
          isHttpsReq && insecureRequested
            ? new https.Agent({ rejectUnauthorized: false })
            : undefined;
        const options = {
          method: 'POST',
          hostname: u.hostname,
          port: u.port || (isHttpsReq ? 443 : 80),
          path: `${u.pathname}${u.search}`,
          headers,
          agent,
        };
        const req = (isHttpsReq ? https : http).request(options, (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () =>
            resolve({ status: res.statusCode || 0, text: data }),
          );
        });
        req.on('error', reject);
        req.write(bodyStr);
        req.end();
      } catch (e) {
        reject(e);
      }
    });

  const { sanitize } = require('./sanitize-artifacts');

  function toSafeMessage(input) {
    try {
      if (!input) return '';
      if (typeof input === 'string') return sanitize(input).slice(0, 500);
      if (typeof input === 'object') {
        const m =
          input.message ||
          input.error ||
          input.detail ||
          input.title ||
          input.reason ||
          '';
        const s = m ? String(m) : JSON.stringify(input);
        return sanitize(s).slice(0, 500);
      }
      return sanitize(String(input)).slice(0, 500);
    } catch {
      return '';
    }
  }

  const { status, text } = await doRequest();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    if (status === 200) {
      // Success with non-JSON body; pass through as-is
      console.log(text);
      process.exit(0);
    }
    // Failure with non-JSON body: log only status and a sanitized, truncated message
    const safeMsg = toSafeMessage(text);
    console.error('Request failed', status, {
      message: safeMsg || 'Request failed',
    });
    process.exit(1);
  }
  if (status < 200 || status >= 300) {
    // Failure with JSON body: avoid dumping entire response; log sanitized message only
    const safeMsg = toSafeMessage(json);
    console.error('Request failed', status, {
      message: safeMsg || 'Request failed',
    });
    process.exit(1);
  }
  console.log(JSON.stringify(json, null, 2));
}

// Node18+ global fetch not used here to allow per-call TLS control
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
