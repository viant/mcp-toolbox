# iplookup_lookup

Lookup geo and ISP information for a list of IP addresses using MaxMind MMDB databases.

## Input

The input **must** be a JSON array. Order is preserved.

```json
[
  {"ip": "8.8.8.8"},
  {"ip": "2001:4860:4860::8888"}
]
```

## Output

The output is a JSON array with one entry per input item.
Per-item errors are returned in the `error` field (the tool does not fail the whole batch).

