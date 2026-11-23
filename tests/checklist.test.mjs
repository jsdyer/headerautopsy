import test from 'node:test';import assert from 'node:assert/strict';
import {securityChecklist} from '../web/checklist.mjs';
test('does not mix headers between HAR responses or count report-only CSP as enforcement',()=>{
 const rows=securityChecklist({rows:[{entry:1,header:'content-security-policy-report-only',reading:'default-src'},{entry:2,header:'content-security-policy',reading:'default-src, frame-ancestors'}]});
 assert.equal(rows.find(r=>r.entry===1&&r.header==='content-security-policy').reading,'Not observed in this capture');
 assert.equal(rows.find(r=>r.entry===2&&r.header==='x-frame-options').reading,'CSP frame-ancestors observed');
 assert.equal(rows.length,12);
});
