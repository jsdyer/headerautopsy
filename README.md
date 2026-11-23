# Header Autopsy

A local HTTP response-header interpreter for CoolCode. Paste response headers, import a browser HAR, or open the measured response from the Market Shadows page. Filter interpreted headers and download a JSON report. HAR imports inspect at most 400 entries and 600 response headers within a 12 MB file.

Use **Compare two responses** to paste a baseline and a candidate header block. The comparison shows status codes, added and removed fields, changed interpretations and new or missing infrastructure clues. Search or filter the differences before saving a privacy-filtered JSON report. Compare the actual 301 redirect with the 200 page response to inspect their published content types and cache instructions.

Comparison treats field names case-insensitively, groups repeated fields and disregards order for recognized Cache-Control and Vary directives. It preserves relative ordering for content and transfer codings, as well as referrer-policy fallback tokens. It compares cookie flag profiles without linking individual cookies. CSP readings include recognized source classes and nonce or hash presence. Fields with matching readings can still differ in redacted values, origins or cookie scope. Use one response block per input.

The app avoids arbitrary remote requests and does not replay capture traffic. Report values are allowlisted interpretations. It drops raw cookies, identifiers, addresses in redirect headers, URLs, and request or response bodies. Header names remain visible. Original pasted text remains in the input until cleared. A HAR file is read locally and its raw content is discarded from application state after parsing.

A header is an observation supplied by a sender. CDN and payment-provider associations are clues to verify. A sanitized HAR may omit credential-related fields. HTTP rules use [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), with browser HAR behavior documented by [Chrome DevTools](https://developer.chrome.com/docs/devtools/network/reference#save-as-har).

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

Deploy `dist/` as a static Pages artifact. No package installation or upstream build download is required.


<!-- coolcode:guide -->
Paste headers or open a HAR locally, then inspect its HTTP status context and security-header checklist. Status notes distinguish cache validation, authentication, rate limits and gateway failures, with direct specification links. A code alone does not establish why a request failed. Use Gov Grade for dated MDN provider grades and TLS evidence.
<!-- /coolcode:guide -->

The built-in captures preserve selected public response fields from ordinary GET requests to [the redirect](https://coolcode.ca/marketshadows) and [the page](https://coolcode.ca/marketshadows/) at 05:35 UTC on 19 November 2026. Headers may differ on another request. The selected fields cover content, dates, cache instructions, location and CORS. Request identifiers and proxy metadata were omitted.


## Added browser workflow

Paste headers or open a HAR locally, then read the security-header checklist for each captured response. Missing headers mean not observed in that capture; CSP frame-ancestors is recognized as a framing-control alternative. Use Gov Grade for dated MDN provider grades and TLS evidence.

## HTTP status context

A pasted status line or HAR response code now opens a contextual reference beside the captured evidence. Comparing responses shows baseline and candidate explanations separately. The guide covers common codes and links each interpretation to its RFC; other valid three-digit codes get a clearly labelled fallback and the IANA registry, rather than an invented meaning. For example, 304 means conditional cache validation, 202 does not establish completion, and 403 alone does not prove a bot block. This remains local interpretation: the app never retries or follows the captured request.

## Expand or customize

Add or revise a code in `web/status-reference.mjs` using its numeric code, title, interpretation and official specification URL or RFC 9110 section. Unknown codes remain usable without a new entry. Keep links to IANA or the relevant published RFC, and add a model assertion for any changed meaning. Run `node --test tests/*.test.mjs` and `python3 scripts/build.py`, then push to `main` to publish through the existing Pages workflow. These authored references have no scheduled network refresh.

Sources: [IANA status registry](https://www.iana.org/assignments/http-status-codes/), [HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15), [Additional HTTP Status Codes](https://www.rfc-editor.org/rfc/rfc6585.html). Reviewed 23 November 2026.
