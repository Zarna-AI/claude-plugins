# Security Review Plugin

Enhanced security review plugin for Claude Code that builds on top of the built-in `/security-review` command with:

- **Stack-specific context** - Security rules tailored to your tech stack (FastAPI, Next.js, Supabase, etc.)
- **Compliance tracking** - SOC II, GDPR, HIPAA, PCI-DSS guidance
- **Audit trail** - Stored reports Claude can reference for historical context
- **Remediation tracking** - Track status of findings (open, in-progress, fixed)
- **Slack integration** - Post scan summaries and reports to your team channel (more integrations coming)

## Team Setup

Complete setup for new team members:

### Step 1: Install the Plugin

```bash
# Add the Zarna plugins marketplace (one-time)
claude plugin marketplace add https://github.com/Zarna-AI/claude-plugins

# Install the plugin for this project
claude plugin install security-scan --scope project
```

### Step 2: Set Up Slack Notifications (Optional but Recommended)

```bash
# Install direnv (manages environment variables per directory)
brew install direnv

# Add direnv hook to your shell
# For zsh (default on macOS):
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc
source ~/.zshrc

# For bash:
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
source ~/.bashrc

# Create .envrc in your project root (already gitignored)
cd /path/to/your/project
echo 'export SECURITY_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"' > .envrc

# Allow direnv to load the file
direnv allow
```

**Note:** Get the Slack webhook URL from your team lead or create one at [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks).

### Step 3: Run Initial Setup (First Team Member Only)

```bash
# Start Claude Code and run:
/security-setup
```

This will:
1. Auto-detect your tech stack
2. Configure compliance targets
3. Set up report storage location
4. Configure Slack notifications
5. Create the directory structure and team config

**Note:** Only one team member needs to run `/security-setup`. The config is committed to the repo, so everyone else gets it automatically.

### For Local Development

```bash
claude --plugin-dir /path/to/claude-plugins/security-scan
```

## Commands

### `/security-review`

Run a security review with full context.

```
/security-review                    # Full review (all areas)
/security-review --area auth        # Focus on authentication
/security-review --area injection   # Focus on injection vulnerabilities
/security-review --save             # Save report to audit trail
/security-review --no-slack         # Skip Slack notification
```

**Available areas:**
| Area | What It Checks |
|------|----------------|
| `auth` | Authentication, authorization, session management, IDOR, privilege escalation |
| `injection` | SQL, command, LDAP, XPath, NoSQL, XXE injection |
| `secrets` | Hardcoded secrets, sensitive data exposure, PII handling |
| `crypto` | Weak algorithms, key management, insecure RNG |
| `validation` | Input validation, sanitization, buffer overflows |
| `logic` | Business logic flaws, race conditions, TOCTOU |
| `config` | Security headers, CORS, insecure defaults |
| `deps` | Dependency vulnerabilities (runs npm audit) |
| `rce` | Remote code execution, deserialization, eval injection |
| `xss` | Cross-site scripting (reflected, stored, DOM-based) |

### `/security-setup`

Configure or reconfigure the plugin settings. Run again when:
- Architecture changes (new tech added/removed)
- Compliance requirements change
- Team notification settings change

## Configuration

Team settings are stored in `{security_path}/team-config.md` (committed to repo):

```yaml
---
# Stack Configuration
stacks:
  - fastapi
  - nextjs
  - supabase

# Compliance Targets
compliance:
  - soc2
  - gdpr

# Paths
security_path: zz_plans/security
reports_path: zz_plans/security/reports
external_path: zz_plans/security/external
remediation_tracker: zz_plans/security/remediation-tracker.md

# History - how many past reports Claude references
past_reports_count: 3

# Notifications (Slack for now, more integrations coming)
slack_webhook: ${SECURITY_SLACK_WEBHOOK}
slack_include_full_report: true
---

## Project Security Notes
Any team-wide security context or exceptions.
```

### Environment Variables

For sensitive values, use environment variables:

```bash
# Add to your shell profile or .env
export SECURITY_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

## Directory Structure

The plugin creates this structure at your configured path:

```
{security_path}/
├── team-config.md              # Shared team settings (committed)
├── reports/                    # Claude's automated scan reports
│   └── YYYY-MM-DD-scan-type.md
├── external/                   # Upload pentests, SOC reports here
│   ├── pentests/
│   └── compliance/
└── remediation-tracker.md      # Track finding status
```

## Uploading External Reports

Place pentest reports, SOC II audit findings, or other external security documents in:

```
{security_path}/external/pentests/     # Pentest reports
{security_path}/external/compliance/   # SOC II, GDPR audits, etc.
```

Claude will reference these when running security reviews to:
- Understand previously identified vulnerabilities
- Track remediation progress
- Avoid re-flagging known/accepted issues

## Adding New Stacks

When your architecture changes:

1. Create a new stack file in `skills/security-context/references/stacks/`
2. Use `_template.md` as a starting point
3. Run `/security-setup` to add the stack to your config

Or manually edit `team-config.md` to add the stack name.

## Components

| Component | Purpose |
|-----------|---------|
| **Skill**: `security-context` | Auto-loads relevant context for security queries |
| **Command**: `/security-review` | Run security reviews with options |
| **Command**: `/security-setup` | Configure the plugin |
| **Agent**: `security-scanner` | Deep autonomous scanning |

## Requirements

- Claude Code CLI
- Node.js (for npm audit)
- Optional: gitleaks, nuclei for enhanced scanning

## Future Integrations

Currently supports Slack notifications. Planned:
- Email notifications
- Microsoft Teams
- Discord
- Custom webhooks

## License

MIT
