# `keyToggle`

Toggles a key down/up. This is the most flexible primitive for chords.

Input:
```json
{ "key": "cmd", "down": "down", "modifiers": [] }
```

Notes:
- `down` is `"down"` or `"up"` (default: `"down"`).
- For key chords, call `keyDown`/`keyUp` (or `keyToggle`) around `keyTap`/`type`.

