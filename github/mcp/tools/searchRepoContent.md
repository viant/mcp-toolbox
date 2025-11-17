Find files by path/content and return previews (read-only). Uses a repo snapshot; does not modify the repo.

Notes:
- Modes: `match` (formerly `matches`/`search`) and `head`.
- `match`: returns snippets around content matches when `queries`/`excludeQueries` are provided.
- `head`: returns the file head only (capped by `bytes`).
- `hits` are byte ranges within the snippet text; `start`/`end` are 1-based line numbers.
