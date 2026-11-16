# Header Autopsy

A local HTTP response-header interpreter for CoolCode. Paste response headers, import a browser HAR, or load the synthetic capture. Filter interpreted headers and download a JSON report. HAR imports inspect at most 400 entries and 600 response headers within a 12 MB file.

The app avoids arbitrary remote requests and does not replay capture traffic. Report values are allowlisted interpretations. It drops raw cookies, identifiers, addresses in redirect headers, URLs, and request or response bodies. Header names remain visible. Original pasted text remains in the input until cleared. A HAR file is read locally and its raw content is discarded from application state after parsing.

A header is an observation supplied by a sender. CDN and payment-provider associations are clues to verify. A sanitized HAR may omit credential-related fields. HTTP rules use [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), with browser HAR behavior documented by [Chrome DevTools](https://developer.chrome.com/docs/devtools/network/reference#save-as-har).

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

Deploy `dist/` as a static Pages artifact. No package installation or upstream build download is required.
