package service

// Config configures the Browser MCP service.
// For now it primarily configures WebDriver installation and output style.
type Config struct {
	// UseData controls whether MCP tool results are returned as structured content.
	// If false, results are returned as JSON text.
	UseData bool

	// InstallDir is where chromedriver/geckodriver binaries will be installed when missing.
	// If empty, defaults to $HOME/.mcp-toolbox/browser/webdriver.
	InstallDir string

	// ForceHeadful removes headless capability args (for monitoring what the agent is doing).
	ForceHeadful bool
}
