# Claude Code Plugins

Shared plugins for Claude Code.

## Available Plugins

| Plugin | Description | Install |
|--------|-------------|---------|
| [security-scan](./security-scan) | Security review with stack-specific context, compliance tracking, and Slack integration | `claude plugins add https://github.com/Zarna-AI/claude-plugins/security-scan` |

## Installation

Install individual plugins using the subdirectory path:

```bash
claude plugins add https://github.com/Zarna-AI/claude-plugins/<plugin-name>
```

## For Team Members

1. Install the plugin(s) you need
2. Set required environment variables (see each plugin's README)
3. Run the plugin's setup command

## Contributing

To add a new plugin:
1. Create a new directory with the plugin name
2. Follow the Claude Code plugin structure
3. Add to the table above
4. Submit a PR
