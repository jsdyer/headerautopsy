import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHAR, parseHeaders } from '../web/model.mjs';
import { SAMPLE } from '../web/sample.mjs';

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
