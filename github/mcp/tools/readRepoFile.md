Read (legacy: download) a file by repository path without cloning the repo. Supports chunked previews using `maxBytes` + `offsetBytes` with MCP continuation hints in the response.

Notes:
- Optional sed: `sedScripts` preview/transform (no repo changes). Flags g/i/m (RE2 regex).
- `applySedToOutput=true` returns transformed content in `text`; otherwise `transformedText` is provided.
- `mode`, `maxBytes`, `offsetBytes`, `lengthBytes` control previews for large files. When limits are set the response includes `returned`, `remaining`, `modeApplied`, and an `extension.Continuation` payload (`continuation.nextRange.bytes`) for follow-up calls.
