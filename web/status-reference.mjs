// Context notes reviewed against RFC 9110, RFC 6585 and the IANA registry.
// This is a bounded interpretation guide, not a complete registry copy.
const IANA = 'https://www.iana.org/assignments/http-status-codes/';
const RFC = 'https://www.rfc-editor.org/rfc/rfc9110.html#section-';
const records = {
  100: ['Continue', 'An interim response: the request has not reached its final outcome.', '15.2.1'],
  101: ['Switching Protocols', 'The connection is changing protocols. Later traffic may no longer be ordinary HTTP responses.', '15.2.2'],
  103: ['Early Hints', 'Preliminary resource hints can arrive before a final response. Do not treat this as the final page status.', 'https://www.rfc-editor.org/rfc/rfc8297.html'],
  200: ['OK', 'The HTTP request succeeded. Application-level results still depend on the response body and request method.', '15.3.1'],
  201: ['Created', 'The request created a resource. Inspect Location when supplied to identify its reported address.', '15.3.2'],
  202: ['Accepted', 'Processing was accepted, but completion is not established. Look for the application’s later result.', '15.3.3'],
  204: ['No Content', 'The request succeeded without response content. An empty body is expected here.', '15.3.5'],
  206: ['Partial Content', 'This is a range response. Inspect Content-Range and the request’s Range field before treating it as a full download.', '15.3.7'],
  301: ['Moved Permanently', 'A permanent redirect. Inspect Location and the subsequent response; some clients may change POST to GET.', '15.4.2'],
  302: ['Found', 'A temporary redirect. Inspect Location and the subsequent response; some clients may change POST to GET.', '15.4.3'],
  303: ['See Other', 'The result is available at another address, normally retrieved with GET or HEAD.', '15.4.4'],
  304: ['Not Modified', 'Conditional cache validation succeeded. The client can reuse its stored representation; this is not a new response body.', '15.4.5'],
  307: ['Temporary Redirect', 'A temporary redirect that preserves the request method. Inspect Location before following it.', '15.4.8'],
  308: ['Permanent Redirect', 'A permanent redirect that preserves the request method. Inspect Location before following it.', '15.4.9'],
  400: ['Bad Request', 'The responder could not process the request as sent. The status alone does not identify the invalid field.', '15.5.1'],
  401: ['Unauthorized', 'Authentication is required or was not accepted. Inspect WWW-Authenticate; this differs from a generic refusal.', '15.5.2'],
  403: ['Forbidden', 'The responder refused this request. The code alone does not distinguish an access policy, bot challenge or other restriction.', '15.5.4'],
  404: ['Not Found', 'No current representation was provided at this address. It can also conceal whether a restricted resource exists.', '15.5.5'],
  405: ['Method Not Allowed', 'The resource does not support this request method. Inspect Allow for methods the responder advertises.', '15.5.6'],
  408: ['Request Timeout', 'The responder did not receive a complete request within its allotted time.', '15.5.9'],
  409: ['Conflict', 'The request conflicts with the resource’s current state. Inspect the application’s explanation before retrying.', '15.5.10'],
  410: ['Gone', 'The responder reports that the resource is no longer available and expects that condition to persist.', '15.5.11'],
  412: ['Precondition Failed', 'A request precondition did not hold. Compare conditional request fields with the current resource.', '15.5.13'],
  413: ['Content Too Large', 'The request content exceeded a limit. A smaller upload or application-specific limit may be relevant.', '15.5.14'],
  415: ['Unsupported Media Type', 'The request representation was not accepted. Check its Content-Type, Content-Encoding and actual format.', '15.5.16'],
  416: ['Range Not Satisfiable', 'The requested range could not be served. Inspect Content-Range when present and verify the requested offsets.', '15.5.17'],
  418: ['Unused in HTTP Semantics', 'Some applications use this as a custom “teapot” response. RFC 9110 reserves the code as unused; inspect the sender’s documentation.', '15.5.19'],
  421: ['Misdirected Request', 'The receiving server could not provide an authoritative response for the target origin.', '15.5.20'],
  422: ['Unprocessable Content', 'The content type and syntax were understood, but its instructions could not be processed.', '15.5.21'],
  426: ['Upgrade Required', 'The responder requires a different protocol. Inspect its Upgrade field.', '15.5.22'],
  428: ['Precondition Required', 'The server requires a conditional request, often to prevent overwriting a newer resource.', 'https://www.rfc-editor.org/rfc/rfc6585.html#section-3'],
  429: ['Too Many Requests', 'The responder reports a rate limit. Inspect Retry-After when supplied; the code does not reveal how the quota is counted.', 'https://www.rfc-editor.org/rfc/rfc6585.html#section-4'],
  431: ['Request Header Fields Too Large', 'The request headers exceeded a limit. Check their total size and individual fields such as Cookie.', 'https://www.rfc-editor.org/rfc/rfc6585.html#section-5'],
  451: ['Unavailable For Legal Reasons', 'The responder reports a legal restriction. The status itself does not verify its legal basis or scope.', 'https://www.rfc-editor.org/rfc/rfc7725.html'],
  500: ['Internal Server Error', 'The responder encountered an unexpected failure. The status alone does not identify the failed component.', '15.6.1'],
  501: ['Not Implemented', 'The responder does not support functionality needed for this request.', '15.6.2'],
  502: ['Bad Gateway', 'A gateway or proxy received an invalid upstream response. This does not by itself locate the failing network hop.', '15.6.3'],
  503: ['Service Unavailable', 'The responder is currently unable to handle the request. Inspect Retry-After when present; maintenance and overload are possible causes.', '15.6.4'],
  504: ['Gateway Timeout', 'A gateway or proxy did not receive its required upstream response in time.', '15.6.5'],
  505: ['HTTP Version Not Supported', 'The responder does not support the request’s major HTTP version.', '15.6.6'],
};
const families = ['Informational', 'Success', 'Redirection', 'Client error', 'Server error'];

export function statusReference(value) {
  if (!Number.isInteger(value) || value < 100 || value > 599) return null;
  const record = records[value];
  return {
    code: value,
    family: families[Math.floor(value / 100) - 1],
    title: record?.[0] || 'No specific interpretation in this guide',
    detail: record?.[1] || 'Check the IANA registry and sender documentation. A three-digit value can be an extension, an unassigned code or a provider-specific convention.',
    reference: record ? (record[2].startsWith('https:') ? record[2] : RFC + record[2]) : IANA,
    registry: IANA,
    specific: Boolean(record),
  };
}

export function statusReferences(values) {
  return [...new Set(values)].map(statusReference).filter(Boolean);
}
