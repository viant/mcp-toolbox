# browserFind

Multi-match element discovery using a Playwright-like `locator` with auto-wait and rich metadata (rect/text/attrs).

This tool is intended for:
- debugging ("why can’t it find the element?")
- resilient scripts (find candidates, then click by returned selector)
- building higher-level locator-based actions in later tools

## Input

- `sessionID`: `host:port` (default `localhost:4444`)
- `locator`: query description
- `maxWaitMs`: wait for matches (default 10000)
- `pollMs`: polling interval (default 200)
- `minMatches`: wait until at least N matches exist (default 1)
- `maxMatches`: returned match cap (default 20)
- `strict`: require exactly 1 match
- `visibleOnly`: filter to visible elements
- `key`: optional output key (stores matches under `result.data[key]`)

### Locator fields

- `css`: base CSS selector to narrow candidates
- `xpath`: base XPath selector to narrow candidates
- `within`: nested locator scoping (container)
- `role`: ARIA role (exact match). Uses explicit `role` attribute, otherwise infers common implicit roles (e.g. `button`, `link`, `textbox`).
- `name`: accessible-ish name (aria-label / aria-labelledby / associated <label> / alt/title/value/placeholder / text), exact/contains by `exact`
- `text`: innerText/textContent, exact/contains by `exact`
- `testID`: matches `data-testid` / `data-test-id` (exact)
- `exact`: applies to `name`/`text` (default false)
- Composition:
  - `any`: union (element can match any locator)
  - `all`: intersection (element must match all locators)
  - `not`: exclusion (exclude elements matching this locator)

## Output

Returns:
- `matches[]`: each has `{selector, tag, text, role, name, attrs, rect, visible}`
- `data[key]`: optional copy of matches when `key` is set

## Example

Find a visible "Sign in" button by text:

```json
{
  "sessionID":"localhost:4444",
  "locator": { "text":"Sign in", "exact":true },
  "visibleOnly": true,
  "strict": false,
  "maxWaitMs": 15000
}
```

Find either "Sign in" or "Log in", scoped within a dialog:

```json
{
  "sessionID":"localhost:4444",
  "locator": {
    "within": { "role":"dialog" },
    "any": [
      { "text":"Sign in", "exact":true },
      { "text":"Log in", "exact":true }
    ]
  },
  "visibleOnly": true,
  "strict": false
}
```
