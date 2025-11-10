Find files by path/content and return previews (read-only). Uses a repo snapshot; does not modify the repo.

Inputs (compact):
- url/ref: repo target. If `ref` is omitted, the default branch is used.
- path/recursive: scope root and traversal.
- include/exclude: path globs.
- queries/excludeQueries: content filters (substrings or `/regex/flags`; RE2; `i` supported).
- caseInsensitive: content search case-insensitivity (defaults to true when queries present).
- mode: `matches` (grep-like snippets) or `head`.
- bytes/lines/maxFiles/maxBlocks: preview shaping and limits.
- skipBinary/maxSize/concurrency: safety/perf knobs.

Example request:
{
  "url": "github.vianttech.com/adelphic/mediator",
  "ref": "master",           // optional; default branch used when omitted
  "path": "/",
  "recursive": true,
  "include": ["**/*.go","**/*.md","docker/**/*.yaml","**/*.yml"],
  "exclude": ["**/vendor/**","**/*_test.go",".git/**"],
  "queries": ["/floor/i","/BidFloor/i","/dealid/i","/pmp/i"],
  "caseInsensitive": true,
  "mode": "matches",
  "bytes": 800,
  "lines": 1,
  "maxFiles": 200,
  "maxBlocks": 3,
  "skipBinary": true,
  "maxSize": 600000,
  "concurrency": 8
}

Example response (truncated):
{
  "ref": "master",
  "sha": "6e35af9e...",
  "stats": {"scanned": 2600, "matched": 201, "truncated": true},
  "files": [
    {
      "path": "base/costallocation/README.md",
      "matches": 26,
      "omitted": 9,
      "snippets": [
        {"start": 23, "end": 31, "text": "...merged window...", "hits": [[5,9],[16,22]]}
      ]
    }
  ]
}

Notes:
- `hits` are byte ranges within the snippet text; `start`/`end` are 1-based line numbers.
- In `head` mode, a single snippet with the head of the file is returned (capped by `bytes`).
