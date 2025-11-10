List paths in a repo (no clone). Returns paths only for compactness.

Inputs:
- url/ref or owner/repo (+ optional alias/domain).
- path/recursive, include/exclude globs.

Example request:
{
  "url": "github.vianttech.com/adelphic/mediator",
  "path": "/",
  "recursive": true,
  "include": ["**/*.go","**/*.md"],
  "exclude": ["**/*_test.go","**/vendor/**",".git/**"]
}

Example response:
{
  "ref": "master",
  "paths": [
    "README.md",
    "app/main.go",
    "docs/guide.md"
  ]
}
