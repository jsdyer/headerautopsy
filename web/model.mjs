const MAX_ROWS = 600;
const MAX_HAR_ENTRIES = 400;
const HEADER_NAME = /^[!#$%&'*+.^_`|~\w-]{1,72}$/;
const KNOWN = Object.freeze({
  'accept-ranges': ['Delivery', 'Describes which range requests the server accepts.'],
  age: ['Cache', 'Seconds this response has been stored or reused by caches.'],
  'cache-control': ['Cache', 'Directives for freshness, reuse, and revalidation.'],
  'content-encoding': ['Delivery', 'How the representation was encoded in transit.'],
  'content-length': ['Delivery', 'Declared representation length in bytes when supplied.'],
  'content-security-policy': ['Security', 'Restricts where resources can load or execute. Source expressions and nonces are omitted.'],
  'content-security-policy-report-only': ['Security', 'Reports policy violations without enforcing this policy. Source expressions are omitted.'],
  'content-type': ['Delivery', 'Sender-declared media type. Parameters are omitted.'],
  'cross-origin-embedder-policy': ['Security', 'Policy for embedding resources from other origins.'],
  'cross-origin-opener-policy': ['Security', 'Controls browsing context group separation.'],
  'cross-origin-resource-policy': ['Security', 'Limits which origins may include this response.'],
  'access-control-allow-origin': ['Security', 'Origins to which browsers may expose a cross-origin response.'],
  'access-control-allow-credentials': ['Security', 'Whether credentialed cross-origin responses can be exposed.'],
  etag: ['Cache', 'An opaque validation tag. The identifier is omitted.'],
  expires: ['Cache', 'An HTTP date after which the response is considered stale.'],
  'last-modified': ['Cache', 'A server-provided modification timestamp.'],
  location: ['Delivery', 'A server instruction to resolve or redirect to another address. The address is omitted.'],
  'permissions-policy': ['Security', 'Controls feature use in the page and its frames. Allowlists are omitted.'],
  'referrer-policy': ['Security', 'Controls how much referrer information the browser may send.'],
  server: ['Infrastructure', 'Optional software or service label supplied by the responder.'],
  'set-cookie': ['Cookies', 'A browser cookie instruction. Its name, value, and scope are omitted.'],
  'strict-transport-security': ['Security', 'Instructs supporting browsers to use HTTPS for this host for a defined duration.'],
  'transfer-encoding': ['Delivery', 'Transfer codings used to convey the HTTP message.'],
  vary: ['Cache', 'Request fields a cache may use to select the appropriate response.'],
  via: ['Infrastructure', 'Optional intermediary information. Proxy identifiers are omitted.'],
  'x-cache': ['Cache', 'An intermediary-provided cache signal. Semantics vary by provider.'],
  'x-content-type-options': ['Security', 'Can tell browsers to honour the declared content type in relevant contexts.'],
  'x-frame-options': ['Security', 'Controls frame embedding for supporting browsers.'],
  'x-powered-by': ['Infrastructure', 'Optional technology label supplied by the responder.'],
});
const VENDOR_HEADERS = Object.freeze({
  'cf-ray': 'Cloudflare', 'cf-cache-status': 'Cloudflare', 'x-amz-cf-id': 'Amazon CloudFront',
  'x-amz-cf-pop': 'Amazon CloudFront', 'x-akamai-transformed': 'Akamai',
  'x-sucuri-id': 'Sucuri', 'x-served-by': 'possible Fastly or another shared-cache convention',
  'x-vercel-id': 'Vercel', 'x-azure-ref': 'Microsoft Azure',
});
const PAYMENT_HOSTS = {
  'stripe.com': 'Stripe', 'stripe.network': 'Stripe', 'moneris.com': 'Moneris',
  'paypal.com': 'PayPal', 'paypalobjects.com': 'PayPal', 'squareup.com': 'Square',
  'adyen.com': 'Adyen', 'braintreegateway.com': 'Braintree',
};
const PRIVATE_HEADERS = /(?:authorization|token|api[-_]?key|session|credential|secret|signature|passw|client[-_]?id|request[-_]?id|forwarded|trace)/i;
const POLICY_DIRECTIVE = /^(?:(?:default|script|style|img|font|connect|frame|worker|media|object|child|manifest|prefetch)-src(?:-elem|-attr)?|frame-ancestors|form-action|base-uri|sandbox|upgrade-insecure-requests|block-all-mixed-content|report-uri|report-to|require-trusted-types-for|trusted-types|geolocation|camera|microphone|clipboard-read|clipboard-write|payment|fullscreen)$/;
const SOURCE_CLASS = /^(?:\*|https?:|data:|blob:|'(?:self|none|unsafe-inline|unsafe-eval|wasm-unsafe-eval|strict-dynamic|unsafe-hashes|report-sample)')$/;
const UNORDERED_LISTS = new Set(['cache-control', 'vary']);

function directiveValue(value, pattern, ordered = false) {
  const matches = value.toLowerCase().split(/[;,]/).map((v) => v.trim().replace(/\s*=\s*/, '='))
    .filter((v) => pattern.test(v));
  return matches.length ? (ordered ? matches : [...new Set(matches)]).join(', ') : 'Present';
}

function policyClasses(value) {
  const entries = value.split(';').map((part) => part.trim().split(/\s+/))
    .filter(([name]) => POLICY_DIRECTIVE.test(name));
  const reading = entries.map(([name, ...values]) => {
    if (!name.includes('-src') && !['frame-ancestors', 'form-action', 'base-uri'].includes(name)) {
      return name + (values.length ? ' (arguments withheld)' : '');
    }
    const parts = values.map((source) => {
      if (SOURCE_CLASS.test(source)) return source;
      if (/^'nonce-/i.test(source)) return 'nonce source';
      if (/^'sha(?:256|384|512)-/i.test(source)) return 'hash source';
      return 'other source withheld';
    });
    return `${name}: ${[...new Set(parts)].sort().join(' · ') || 'empty source list'}`;
  });
  if (new Set(entries.map(([name]) => name)).size === entries.length) reading.sort();
  return reading.length ? reading.join('; ') : 'Present';
}

function summary(name, value, comparison) {
  if (name === 'set-cookie') {
    const flags = value.split(';').slice(1).map((v) => v.trim().toLowerCase().replace(/\s*=\s*/, '='));
    const visible = flags.filter((v) => /^(?:secure|httponly|partitioned|samesite\s*=\s*(?:lax|strict|none))$/.test(v));
    return visible.length ? visible.join(', ') : 'No recognized security attributes';
  }
  if (name === 'access-control-allow-credentials') return /^true$/i.test(value) ? 'true' : 'Unrecognized value';
  if (PRIVATE_HEADERS.test(name) || name === 'cookie') return 'Sensitive value omitted';
  if (name === 'age' || name === 'content-length') return /^\d{1,15}$/.test(value) ? value : 'Unrecognized numeric value';
  if (name === 'cache-control') return directiveValue(value, /^(?:public|private|no-cache|no-store|no-transform|must-revalidate|proxy-revalidate|immutable|must-understand|(?:max-age|s-maxage|stale-while-revalidate|stale-if-error)=\d{1,12})$/);
  if (name === 'strict-transport-security') return directiveValue(value, /^(?:max-age=\d{1,12}|includesubdomains|preload)$/);
  if (name.startsWith('content-security-policy') || name === 'permissions-policy') {
    if (comparison && name.startsWith('content-security-policy')) return policyClasses(value);
    const names = value.split(name === 'permissions-policy' ? ',' : ';').map((v) => v.trim().split(/[\s=]/, 1)[0]);
    const known = names.filter((v) => POLICY_DIRECTIVE.test(v));
    return known.length ? [...new Set(known)].slice(0, 25).join(', ') : 'Present';
  }
  if (name === 'content-type') {
    const type = value.trim().toLowerCase().split(';', 1)[0];
    return /^(?:text|image|video|audio|font|application|multipart|message|model)\/[a-z0-9.+_-]{1,64}$/.test(type) ? type : 'Present';
  }
  if (name === 'content-encoding' || name === 'transfer-encoding') return directiveValue(value, /^(?:identity|gzip|br|deflate|compress|zstd|chunked|trailers)$/, true);
  if (name === 'access-control-allow-origin') return value === '*' || value === 'null' ? value : 'Specific value omitted';
  if (name === 'x-frame-options') return directiveValue(value, /^(?:deny|sameorigin)$/);
  if (name === 'x-content-type-options') return directiveValue(value, /^nosniff$/);
  if (name === 'referrer-policy') return directiveValue(value, /^(?:no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|same-origin|strict-origin|strict-origin-when-cross-origin|unsafe-url)$/, true);
  if (name.startsWith('cross-origin-')) return directiveValue(value.split(';', 1)[0], /^(?:unsafe-none|same-origin|same-origin-allow-popups|same-site|cross-origin|require-corp|credentialless|noopener-allow-popups)$/);
  if (name === 'x-cache' || name === 'cf-cache-status') {
    const signal = /^\s*(hit|miss|stale|bypass|expired|updating|revalidated|dynamic)(?:\b|$)/i.exec(value);
    return signal ? signal[1].toUpperCase() : 'Value withheld';
  }
  if (name === 'expires' || name === 'last-modified') {
    const date = Date.parse(value);
    return Number.isFinite(date) ? new Date(date).toISOString() : 'Unrecognized date';
  }
  if (name === 'vary') return directiveValue(value, /^(?:\*|accept|accept-encoding|accept-language|origin|user-agent|cookie|authorization)$/);
  if (name === 'accept-ranges') return directiveValue(value, /^(?:bytes|none)$/);
  return 'Value withheld';
}

function projectHeader(name, value, comparison = false) {
  const key = String(name).trim().toLowerCase();
  if (!HEADER_NAME.test(key)) return null;
  const vendor = Object.hasOwn(VENDOR_HEADERS, key) ? VENDOR_HEADERS[key] : null;
  const model = Object.hasOwn(KNOWN, key) ? KNOWN[key] : null;
  const group = model?.[0] ?? (vendor ? 'Infrastructure' : PRIVATE_HEADERS.test(key) || key === 'cookie' ? 'Sensitive' : 'Other');
  const detail = model?.[1] ?? (vendor ? `A header name consistent with ${vendor}. It may have been set by another system.` : 'A header with no built-in interpretation.');
  return { header: key, group, detail, reading: summary(key, String(value ?? '').slice(0, 12000), comparison), vendor };
}

function finish(source, status, rows, hosts, limited) {
  const findings = [];
  const vendors = new Set(rows.map((r) => r.vendor).filter(Boolean));
  for (const vendor of vendors) findings.push({ title: vendor, level: 'Clue', detail: 'One or more observed header names are consistent with this supplier. Verify with further evidence.' });
  const credentialed = new Set(rows.filter((r) => r.header === 'access-control-allow-credentials' && r.reading === 'true').map((r) => r.entry));
  if (rows.some((r) => r.header === 'access-control-allow-origin' && r.reading === '*' && credentialed.has(r.entry))) {
    findings.push({ title: 'Wildcard origin with credentials', level: 'Review', detail: 'Browsers reject access to credentialed responses with a wildcard allowed origin.' });
  }
  if (rows.some((r) => r.header === 'set-cookie' && r.reading.includes('samesite=none') && !r.reading.includes('secure'))) {
    findings.push({ title: 'Cookie using SameSite=None', level: 'Review', detail: 'A matching captured cookie line has no recognized Secure attribute. Browsers normally require that pairing.' });
  }
  for (const item of hosts) findings.push({ title: item.provider, level: 'Clue', detail: `The capture contains requests to ${item.host}. A request destination by itself does not establish a payment flow.` });
  return { source, status, rows, findings, limited };
}

export function parseHeaders(input, { comparison = false } = {}) {
  if (typeof input !== 'string' || input.length > 700000) throw new Error('Paste up to 700,000 characters at a time.');
  const pairs = [];
  const codes = [];
  let rawCount = 0;
  for (const line of input.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    if (!line.trim()) {
      if (pairs.length) break;
      continue;
    }
    const response = /^HTTP\/\d+(?:\.\d+)?[ \t]+([1-5]\d\d)\b/i.exec(line);
    if (response) { codes.push(Number(response[1])); continue; }
    if (/^[ \t]/.test(line) && pairs.length) {
      pairs[pairs.length - 1][1] = (pairs[pairs.length - 1][1] + ' ' + line.trim()).slice(0, 12000);
      continue;
    }
    const pos = line.indexOf(':');
    if (pos < 1 || !HEADER_NAME.test(line.slice(0, pos).trim())) {
      if (pairs.length || codes.length) break;
      continue;
    }
    rawCount++;
    if (pairs.length === MAX_ROWS) break;
    pairs.push([line.slice(0, pos), line.slice(pos + 1).trim()]);
  }
  const rows = pairs.map(([name, value]) => projectHeader(name, value, comparison)).filter(Boolean);
  if (!rows.length) throw new Error('No HTTP header lines were found. Use name: value syntax.');
  return finish('Pasted response headers', codes.slice(0, 25), rows, [], rawCount > rows.length);
}

function groupRows(rows) {
  const groups = new Map();
  for (const row of rows) {
    if (!groups.has(row.header)) groups.set(row.header, []);
    groups.get(row.header).push(row);
  }
  return groups;
}

function readings(name, rows) {
  const values = rows.map((row) => row.reading);
  if (UNORDERED_LISTS.has(name)) {
    return values.length ? [[...new Set(values.flatMap((value) => value.split(', ')))].sort().join(', ')] : [];
  }
  if (name === 'strict-transport-security') return values.map((value) => value.split(', ').sort().join(', '));
  if (name === 'set-cookie') return values.map((value) => value.split(', ').sort().join(', ')).sort();
  if (['content-encoding', 'transfer-encoding', 'referrer-policy'].includes(name)) {
    return values.length ? [values.join(', ')] : [];
  }
  return values;
}

function describeSide(label, input) {
  try { return parseHeaders(input, { comparison: true }); }
  catch (error) { throw new Error(`${label} response: ${error.message}`); }
}

export function compareHeaderSets(baseline, candidate) {
  const before = describeSide('Baseline', baseline);
  const after = describeSide('Candidate', candidate);
  const left = groupRows(before.rows);
  const right = groupRows(after.rows);
  const names = [...new Set([...left.keys(), ...right.keys()])].sort();
  const headers = names.map((header) => {
    const a = left.get(header) ?? [];
    const b = right.get(header) ?? [];
    const baselineReadings = readings(header, a);
    const candidateReadings = readings(header, b);
    const change = !a.length ? 'Added' : !b.length ? 'Removed'
      : JSON.stringify(baselineReadings) === JSON.stringify(candidateReadings) ? 'Matching' : 'Changed';
    const { group, detail } = a[0] ?? b[0];
    return { header, group, detail, change, baselineReadings, candidateReadings };
  });
  const introduced = after.findings.filter((finding) => !before.findings.some((f) => f.title === finding.title));
  const cleared = before.findings.filter((finding) => !after.findings.some((f) => f.title === finding.title));
  return {
    source: 'Response header comparison',
    baseline: { status: before.status, limited: before.limited },
    candidate: { status: after.status, limited: after.limited },
    headers, introduced, cleared,
  };
}

export function parseHAR(input) {
  if (typeof input !== 'string' || input.length > 12000000) throw new Error('Import a HAR file up to 12 MB.');
  let json;
  try { json = JSON.parse(input.replace(/^\uFEFF/, '')); } catch { throw new Error('This file is not valid JSON.'); }
  const entries = json?.log?.entries;
  if (!Array.isArray(entries) || !entries.length) throw new Error('This HAR has no request entries.');
  const rows = [];
  const statuses = new Set();
  const hosts = new Map();
  let limited = entries.length > MAX_HAR_ENTRIES;
  for (const [index, entry] of entries.slice(0, MAX_HAR_ENTRIES).entries()) {
    let host = '';
    try {
      const url = new URL(entry?.request?.url ?? '');
      if (url.protocol === 'http:' || url.protocol === 'https:') host = url.hostname.toLowerCase().replace(/\.$/, '');
    } catch { /* Invalid URLs do not contribute provider clues. */ }
    if (host) {
      const service = Object.entries(PAYMENT_HOSTS).find(([domain]) => host === domain || host.endsWith('.' + domain));
      if (service && !hosts.has(service[1])) hosts.set(service[1], { host: service[0], provider: service[1] });
    }
    const status = entry?.response?.status;
    if (Number.isInteger(status) && status >= 100 && status <= 599) statuses.add(status);
    const response = entry?.response?.headers;
    if (!Array.isArray(response)) continue;
    for (const field of response) {
      if (rows.length === MAX_ROWS) { limited = true; break; }
      if (typeof field?.name !== 'string' || typeof field?.value !== 'string') continue;
      const row = projectHeader(field.name, field.value);
      if (row) rows.push({ ...row, entry: index + 1 });
    }
  }
  if (!rows.length && !hosts.size) throw new Error('No response headers or known provider clues were available in this capture.');
  return finish('HAR response headers', [...statuses], rows, [...hosts.values()], limited);
}
