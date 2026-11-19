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
Choose Compare two responses and open the captured redirect and page. The path without a final slash returned 301. The destination returned 200 and a max-age of 600 seconds.
<!-- /coolcode:guide -->

The built-in captures preserve selected public response fields from ordinary GET requests to [the redirect](https://coolcode.ca/marketshadows) and [the page](https://coolcode.ca/marketshadows/) at 05:35 UTC on 19 November 2026. Headers may differ on another request. The selected fields cover content, dates, cache instructions, location and CORS. Request identifiers and proxy metadata were omitted.
