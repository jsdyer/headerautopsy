import test from 'node:test';
import assert from 'node:assert/strict';
import { compareHeaderSets, parseHAR, parseHeaders } from '../web/model.mjs';
import { COMPARISON_SAMPLE, SAMPLE } from './header-fixtures.mjs';

test('explains response headers, strips opaque fields and classifies CDN clues', () => {
  const result = parseHeaders(SAMPLE);
  assert.deepEqual(result.status, [200]);
  assert.ok(result.rows.some((r) => r.header === 'set-cookie' && r.reading.includes('httponly')));
  assert.ok(result.rows.some((r) => r.header === 'content-security-policy' && r.reading === 'default-src, script-src'));
  assert.ok(result.findings.some((f) => f.title === 'Cloudflare'));
  assert.doesNotMatch(JSON.stringify(result), /fictional|test-session|Example Edge/);
});

test('extracts responses only and uses exact service domain boundaries', () => {
  const result = parseHAR(JSON.stringify({ log: { entries: [
    { request: { url: 'https://js.stripe.com/a?password=hidden', headers: [{ name: 'authorization', value: 'bearer' }] }, response: { status: 204, headers: [{ name: 'Cache-Control', value: 'no-store' }] }},
    { request: { url: 'https://moneris.com.example.net/a' }, response: { status: 200 }},
  ] }}));
  assert.deepEqual(result.rows.map((r) => r.header), ['cache-control']);
  assert.deepEqual(result.findings.map((f) => f.title), ['Stripe']);
  assert.doesNotMatch(JSON.stringify(result), /bearer|password|example.net/);
});

test('reports a narrow CORS and cookie review signal', () => {
  const result = parseHeaders('Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nSet-Cookie: a=x; SameSite=None');
  assert.equal(result.findings.length, 2);
  assert.throws(() => parseHAR('{"requests":[]}'), /no request entries/);
  assert.throws(() => parseHeaders('anything'), /No HTTP header lines/);
});

test('normalizes separate Cache-Control and Vary lines while preserving ordered encodings', () => {
  const report = compareHeaderSets([
    'CACHE-CONTROL: public, max-age=300', 'cache-control: public', 'Vary: Origin, Accept-Encoding',
    'Content-Encoding: gzip', 'Content-Encoding: br', 'Referrer-Policy: no-referrer, origin, no-referrer',
  ].join('\n'), [
    'Vary: accept-encoding', 'vary: origin', 'cache-control: max-age=300, public',
    'Content-Encoding: br, gzip', 'Referrer-Policy: no-referrer, origin',
  ].join('\n'));
  assert.deepEqual(report.headers.map(({ header, change }) => [header, change]), [
    ['cache-control', 'Matching'], ['content-encoding', 'Changed'], ['referrer-policy', 'Changed'], ['vary', 'Matching'],
  ]);
});

test('redacts identifiers while showing CSP classes, cookie flags and status changes', () => {
  const report = compareHeaderSets(SAMPLE, COMPARISON_SAMPLE);
  assert.deepEqual([report.baseline.status, report.candidate.status], [[200], [302]]);
  const byName = Object.fromEntries(report.headers.map((row) => [row.header, row]));
  assert.equal(byName['x-request-id'].change, 'Matching');
  assert.equal(byName.location.change, 'Added');
  assert.equal(byName.age.change, 'Removed');
  assert.equal(byName['cache-control'].change, 'Changed');
  assert.match(byName['content-security-policy'].candidateReadings[0], /frame-ancestors: 'none'/);
  assert.match(byName['content-security-policy'].candidateReadings[0], /nonce source/);
  assert.match(byName['set-cookie'].candidateReadings[0], /samesite=strict/);
  assert.doesNotMatch(JSON.stringify(report), /fictional|test-session|example.com|Example Edge/i);
  assert.throws(() => compareHeaderSets(SAMPLE, ''), /Candidate response:/);
});

test('compares cookie flag profiles without linking values and reports new review clues', () => {
  const report = compareHeaderSets(
    'Set-Cookie: one=alpha; Secure; HttpOnly\nSet-Cookie: two=beta; SameSite=Lax; Secure',
    'set-cookie: second=gamma; Secure; SameSite=Lax; Domain=hidden.test\nset-cookie: first=delta; HttpOnly; Secure\nCF-Ray: edge-id\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true',
  );
  assert.equal(report.headers.find(({ header }) => header === 'set-cookie').change, 'Matching');
  assert.deepEqual(report.introduced.map((finding) => finding.title), ['Cloudflare', 'Wildcard origin with credentials']);
  assert.equal(report.cleared.length, 0);
  assert.doesNotMatch(JSON.stringify(report), /alpha|gamma|hidden.test|edge-id/);
});
