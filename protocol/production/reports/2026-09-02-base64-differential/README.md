# A signed topology two implementations disagreed about

`escaped.json` is `canonical.json` with the JSON escape `\n` inserted into the
authority signature field. It stays valid JSON, so both parsers read it; the
disagreement is about base64 alone.

| implementation | canonical.json | escaped.json |
|---|---|---|
| Go, before the fix | accepted | **accepted** |
| Python reference (`validate=True`) | accepted | refused, "Only base64 data is allowed" |
| Go, after the fix | accepted | refused, "invalid base64 or length" |

Reproduce the Python half:

    python3 -c 'import base64,sys; sys.path.insert(0,"conformance/reference"); \
      import nomadtopology; \
      nomadtopology.verify(open("runtime/evidence/base64-differential/escaped.json","rb").read(), \
        base64.b64decode(open("runtime/evidence/base64-differential/authority.b64").read()))'

The Go half before the fix was `base64.StdEncoding.Strict().DecodeString`,
which ignores `\r` and `\n` wherever they appear -- `Strict()` constrains the
final quantum's padding bits and nothing else.

Regression: `live/topology/canonicalb64_test.go` and
`live/strictjson/base64_test.go`. See EVIDENCE_INDEX F-18.
