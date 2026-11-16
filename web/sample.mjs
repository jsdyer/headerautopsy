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
