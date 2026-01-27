# Desktop MCP Server

This package provides a Desktop MCP server for local UI automation (mouse, keyboard, screen).

It follows the same tool + service pattern as `browser/`:
- Tool definitions live in `desktop/mcp/tools/*.md` and are embedded by `desktop/mcp/tool.go`.
- Tool implementations live in `desktop/service`.

## Build / Run
    
```bash
go run ./desktop/cmd/desktop-mcp -a :5010
```

Notes:
- This server uses `github.com/go-vgo/robotgo` (cgo). On macOS you may need to grant Accessibility / Screen Recording permissions for the hosting binary.

