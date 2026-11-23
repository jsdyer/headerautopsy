import test from 'node:test';
import assert from 'node:assert/strict';
import {statusReference, statusReferences} from '../web/status-reference.mjs';

test('cache, authentication, rate-limit and gateway statuses retain their distinctions', () => {
  assert.match(statusReference(304).detail, /stored representation/);
  assert.match(statusReference(401).detail, /WWW-Authenticate/);
  assert.match(statusReference(403).detail, /code alone does not distinguish/);
  assert.match(statusReference(429).detail, /Retry-After/);
  assert.match(statusReference(502).detail, /upstream/);
  assert.match(statusReference(202).detail, /completion is not established/);
});
test('unknown provider codes remain unknown, with a registry reference', () => {
  const result=statusReference(599);
  assert.equal(result.specific,false);
  assert.equal(result.family,'Server error');
  assert.equal(result.reference,result.registry);
  assert.match(statusReference(418).title,/Unused/);
});
test('only valid observed integers are interpreted and repeated statuses are deduplicated', () => {
  for(const value of [0,99,600,200.5,'200',null,'<script>']) assert.equal(statusReference(value),null);
  assert.deepEqual(statusReferences([200,200,304,0]).map(x=>x.code),[200,304]);
  for(let code=100;code<=599;code++) assert.match(statusReference(code).reference,/^https:\/\/(www\.rfc-editor\.org|www\.iana\.org)\//);
});
