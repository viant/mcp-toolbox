Download a file by repository path (no clone).

Notes:
- Optional sed: `sedScripts` preview/transform (no repo changes). Flags g/i/m (RE2 regex).
- `applySedToOutput=true` returns transformed content in `text`; otherwise `transformedText` is provided.

Example:
{"url":"github.example.com/org/repo","path":"README.md","sedScripts":["s/old/new/g"],"applySedToOutput":true}

Examples:
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "path":"README.md", "ref":"main"}
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "path":"path/to/file.go"}
