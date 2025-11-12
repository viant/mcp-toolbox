Find files by path/content and return previews (read-only). Uses a repo snapshot; does not modify the repo.

Notes:
- `hits` are byte ranges within the snippet text; `start`/`end` are 1-based line numbers.
- In `head` mode, a single snippet with the head of the file is returned (capped by `bytes`).
