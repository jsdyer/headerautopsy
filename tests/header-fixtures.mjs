export const SAMPLE = `HTTP/2 200
content-type: text/html; charset=utf-8
cache-control: public, max-age=300
age: 91
cf-cache-status: HIT
cf-ray: fictional-correlation-id
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: default-src 'self'; script-src 'self' 'nonce-fictional-secret'
referrer-policy: strict-origin-when-cross-origin
set-cookie: test-session=fictional-auth-token; Path=/; Secure; HttpOnly; SameSite=Lax
server: Example Edge
x-request-id: fictional-request-id`;

export const COMPARISON_SAMPLE = `HTTP/2 302
content-type: text/html; charset=utf-8
cache-control: no-store
cf-cache-status: BYPASS
cf-ray: fictional-new-edge-id
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: default-src 'self'; script-src 'self' 'nonce-fictional-second-secret'; frame-ancestors 'none'
referrer-policy: no-referrer
location: https://example.com/continue?code=fictional-redirect-secret
set-cookie: test-session=fictional-new-auth-token; Path=/; Secure; HttpOnly; SameSite=Strict
server: Example Edge
x-request-id: fictional-new-request-id`;
