#!/usr/bin/env node
// Simple client that calls the a5c endpoint to create a GitHub App installation token
// Usage: node scripts/call-a5c-app-installation-token.js --base https://your.app --owner o --repo r --run 123 --app 456 [--insecure]

const args = require('node:process').argv.slice(2);

const https = require('https');
const http = require('http');
const fs = require('fs');

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
  let local = false;
  try {
    const u = new URL(base);
    isHttps = u.protocol === 'https:';
    isHttp = u.protocol === 'http:';
    
  } catch {}
  // Warn when calling over plain HTTP, which is insecure; allow localhost without extra verbiage
  const suppressHttpWarn = ['1', 'true', 'yes'].includes(
    val(process.env.A5C_SUPPRESS_HTTP_WARNING),
  );
  if (isHttp && !suppressHttpWarn) {
      console.error(
        `Warning: using insecure HTTP base URL (${base}). Prefer HTTPS in non-local environments.`,
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

  
  // Case-insensitive helper
  const I = 'i';
  
  // 1) STATIC_PATTERNS (ordered)
  // Keep changes minimal and aligned with prior style: explicit patterns first
  const STATIC_PATTERNS = [
    // Mask generic OAuth-style query parameters in URLs: access_token, refresh_token, id_token, token
    // code= is handled separately with scoping logic (see maskCodeParams)
    {
      re: /([?&](?:access_token|refresh_token|id_token|token)=)[^&\s#]+/gi,
      replace: '$1***',
    },
  
    // GitLab PATs: glpat-<20+ allowed chars>
    { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/gi, replace: '***' },
  
    // Prefer full redaction for AWS Secret Access Keys (explicit 40-char secret) in common shapes
    // ENV or shell: AWS_SECRET_ACCESS_KEY=xxxxxxxxxx (40)
    {
      re: /(\bAWS_SECRET_ACCESS_KEY\b\s*[:=]\s*['"]?)[A-Za-z0-9\/+=]{40}(['"]?)/gi,
      replace: '$1***$2',
    },
    // JSON: "awsSecretAccessKey": "xxxxxxxxxx" (40)
    {
      re: /(\bawsSecretAccessKey\b\s*:\s*")[A-Za-z0-9\/+=]{40}(")/gi,
      replace: '$1***$2',
    },
  
    // Discord bot token - strict known 3-part token
    { re: /\b(?:[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b/g, replace: '***' },
    // Discord bot token - refined fallback: 3 segments with Discord-like lengths, avoid typical JWT (eyJ...)
    // First: 24 alnum (not starting with eyJ), Second: exactly 6 (not starting with eyJ), Third: 27
    {
      re: /\b(?!eyJ)[A-Za-z\d]{24}\.(?!eyJ)[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b/g,
      replace: '***',
    },
  ];
  
  // 2) ENV/assignment pass: redact values for clearly sensitive keys
  const SENSITIVE_KEY_RE =
    /(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|CLIENT_SECRET|CREDENTIAL|WEBHOOK)/i;
  
  function maskEnvStyle(line) {
    // KEY=VALUE or KEY:=VALUE (docker). Preserve structure and trailing content.
    // For quoted values, scan to the real closing quote while skipping escaped quotes (\' and \").
    const envHeadRe = /(\b[A-Z0-9_]{3,}\b)(\s*[:=]\s*)(.*)/;
    const m = envHeadRe.exec(line);
    if (!m) return line;
    const [, key, sep, rest] = m;
    if (!SENSITIVE_KEY_RE.test(key)) return line;
  
    let newRest = rest;
    if (rest.startsWith('"') || rest.startsWith("'")) {
      const q = rest[0];
      let i = 1;
      while (i < rest.length) {
        const ch = rest[i];
        if (ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === q) {
          break;
        }
        i++;
      }
      if (i < rest.length && rest[i] === q) {
        newRest = q + '***' + q + rest.slice(i + 1);
      } else {
        // No closing quote found; fall back to conservative replace of the first token
        const token = rest.split(/\s|#/)[0];
        newRest = rest.replace(token, token[0] + '***');
      }
    } else {
      // Unquoted: replace contiguous non-space, non-# value with ***
      const m2 = /^[^\s#]+/.exec(rest);
      if (m2) {
        newRest = rest.replace(m2[0], '***');
      }
    }
  
    return line.replace(envHeadRe, (_s, k, s) => `${k}${s}${newRest}`);
  }
  
  // 3) JSON pass: sanitize { "token": "..." } like shapes
  const JSON_KEY_VALUE_RE =
    /(\"(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|password|api[_-]?key|client[_-]?secret|webhook[_-]?secret)\"\s*:\s*\")(.*?)(\")/gi;
  
  function sanitize(text) {
    let out = text;
    // Static patterns pass
    for (const { re, replace } of STATIC_PATTERNS) {
      out = out.replace(re, replace);
    }
  
    // Scoped code= masking pass
    out = maskCodeParams(out);
  
    // Line-oriented ENV pass
    out = out
      .split(/\r?\n/)
      .map((line) => maskEnvStyle(line))
      .join('\n');
  
    // JSON pass
    out = out.replace(JSON_KEY_VALUE_RE, (_s, p1, _val, p3) => `${p1}***${p3}`);
  
    return out;
  }
  
  function maskCodeParams(text) {
    const mode = String(process.env.SANITIZE_CODE_MASK || 'scoped').toLowerCase();
    if (mode === 'off') return text;
    const lines = text.split(/\r?\n/);
    const out = lines.map((line) => {
      // quick accept-all mode
      if (mode === 'all') {
        return line.replace(/([?&]code=)([^&#\s]+)/gi, '$1***');
      }
      // scoped mode: check context and value shape
      // If line includes typical callback indicators, mask code params
      const isCallbackContext = /(callback|oauth|oidc|api\/auth\/callback)/i.test(
        line,
      );
      if (isCallbackContext) {
        return line.replace(/([?&]code=)([^&#\s]+)/gi, '$1***');
      }
      // Otherwise, selectively mask only when value looks like an OAuth code
      return line.replace(/([?&]code=)([^&#\s]+)/gi, (m, p1, val) => {
        const looksCode = val.length >= 20 && /^[A-Za-z0-9._~\-]+$/.test(val);
        return looksCode ? `${p1}***` : m;
      });
    });
    return out.join('\n');
  }
  
  function sanitizeFileInPlace(filePath) {
    const buf = fs.readFileSync(filePath);
    const content = buf.toString('utf8');
    const cleaned = sanitize(content);
    if (cleaned !== content) {
      fs.writeFileSync(filePath, cleaned);
    }
  }

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
