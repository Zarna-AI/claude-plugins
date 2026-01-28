---
description: Set up or reconfigure the security review plugin for your project
allowed-tools: Read, Glob, Grep, Bash(ls:*, test:*, mkdir:*, which:*), Write, AskUserQuestion
---

# Security Review Plugin Setup

Configure the security review plugin for this project. This creates the team configuration and directory structure.

## Step 1: Check Existing Configuration

Search for existing configuration:
- `**/security/team-config.md`
- `**/zz_plans/security/team-config.md`

If found, ask user:
- "Found existing configuration at [path]. Would you like to reconfigure or keep existing settings?"

## Step 2: Auto-Detect Technology Stack

Scan the repository for technology indicators:

### Frontend Detection
- `package.json` with next/react → Next.js
- `package.json` with vue → Vue.js
- `package.json` with angular → Angular
- `package.json` with svelte → Svelte

### Backend Detection
- `requirements.txt` or `pyproject.toml` with fastapi → FastAPI
- `requirements.txt` with django → Django
- `requirements.txt` with flask → Flask
- `package.json` with express → Express.js
- `go.mod` → Go
- `Cargo.toml` → Rust

### Database/Services Detection
- Supabase client imports or SUPABASE env vars → Supabase
- Qdrant client imports or QDRANT env vars → Qdrant
- Firebase imports → Firebase
- Prisma schema → Prisma
- MongoDB imports → MongoDB
- PostgreSQL/psycopg imports → PostgreSQL
- Redis imports → Redis

### Cloud/Infrastructure
- AWS SDK imports → AWS
- GCP imports → Google Cloud
- Azure imports → Azure

Present detected stack to user:

"I detected the following technologies in your codebase:
- [List detected technologies]

Is this correct? Are there any technologies I missed or incorrectly identified?"

Use AskUserQuestion to confirm and allow additions/removals.

## Step 3: Configure Compliance Targets

Ask the user about compliance requirements:

"Which compliance frameworks are relevant to your project?"

Options (multi-select):
- SOC II (Service Organization Control)
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability)
- PCI-DSS (Payment Card Industry Data Security Standard)
- None / Not sure yet

## Step 4: Configure Report Storage

Ask where to store security reports:

"Where would you like to store security reports and tracking files?"

Suggest default based on project structure:
- If `zz_plans/` exists: `zz_plans/security`
- Otherwise: `.security` or `docs/security`

Let user specify custom path if preferred.

## Step 5: Configure Notifications (Optional)

Ask about Slack integration:

"Would you like to configure Slack notifications for security scan results?"

If yes:
- Ask for Slack webhook URL (or note to set SECURITY_SLACK_WEBHOOK env var)
- Ask if full report should be included or just summary

Note: More integrations (email, Teams) coming in future versions.

## Step 6: Check Required Tools

Verify optional security tools are available:

```bash
which npm        # For npm audit
which safety     # For Python dependency scanning
which gitleaks   # For secrets detection
which nuclei     # For vulnerability scanning
```

Report which tools are available and which are missing:

"Security tool availability:
- npm audit: [Available/Not found]
- safety (Python): [Available/Not found - install with: pip install safety]
- gitleaks: [Available/Not found - install with: brew install gitleaks]
- nuclei: [Available/Not found - install with: brew install nuclei]

Missing tools will limit some scanning capabilities but are not required."

## Step 7: Create Directory Structure

Create the security directory structure at the configured path:

```
{security_path}/
├── team-config.md
├── reports/
├── external/
│   ├── pentests/
│   └── compliance/
└── remediation-tracker.md
```

## Step 8: Generate Configuration File

Create `{security_path}/team-config.md`:

```markdown
---
# Security Review Plugin - Team Configuration
# This file is committed to the repository and shared with the team.
# Last updated: [date]

# Technology Stack
# Add or remove technologies as your architecture changes
stacks:
  - [detected/confirmed stacks]

# Compliance Targets
# Frameworks that inform security review criteria
compliance:
  - [selected compliance targets]

# Report Storage
security_path: [configured path]
reports_path: [configured path]/reports
external_path: [configured path]/external
remediation_tracker: [configured path]/remediation-tracker.md

# Historical Context
# Number of past reports Claude references for context
past_reports_count: 3

# Notifications
# Set SECURITY_SLACK_WEBHOOK environment variable with your webhook URL
slack_webhook: ${SECURITY_SLACK_WEBHOOK}
slack_include_full_report: true

# Scan Tracking
last_scan: null
last_scan_type: null
---

## Project Security Notes

Add any project-specific security context here:

- Known security exceptions or accepted risks
- Areas requiring special attention
- Third-party security assessments
- Compliance deadlines or requirements

## Architecture Notes

[Brief description of security-relevant architecture decisions]

## External Report Locations

When you receive external security assessments, place them in:
- `external/pentests/` - Third-party penetration test reports
- `external/compliance/` - SOC II, GDPR audits, etc.

Claude will reference these during security reviews.
```

## Step 9: Create Remediation Tracker

Create `{security_path}/remediation-tracker.md`:

```markdown
# Security Remediation Tracker

Track the status of security findings across scans.

Last Updated: [date]

## Open Findings

| ID | Severity | Area | Description | Found | Owner |
|----|----------|------|-------------|-------|-------|
| | | | | | |

## In Progress

| ID | Severity | Area | Description | Started | Owner | PR/Branch |
|----|----------|------|-------------|---------|-------|-----------|
| | | | | | | |

## Fixed

| ID | Severity | Area | Description | Fixed | Verified |
|----|----------|------|-------------|-------|----------|
| | | | | | |

## Accepted Risk

| ID | Severity | Area | Description | Reason | Approved By | Date |
|----|----------|------|-------------|--------|-------------|------|
| | | | | | | |

---

## How to Use This Tracker

1. After each security scan, add new findings to "Open Findings"
2. When starting remediation, move to "In Progress" with PR/branch link
3. After fix is deployed and verified, move to "Fixed"
4. For accepted risks, document reasoning and approval

## Finding ID Convention

Use format: `SEC-YYYY-NNN` (e.g., SEC-2026-001)
```

## Step 10: Summary and Next Steps

Present summary:

"Security review plugin configured successfully!

**Configuration:**
- Path: [security_path]
- Stacks: [list]
- Compliance: [list]
- Slack: [configured/not configured]

**Created files:**
- [security_path]/team-config.md
- [security_path]/remediation-tracker.md
- [security_path]/reports/ (directory)
- [security_path]/external/pentests/ (directory)
- [security_path]/external/compliance/ (directory)

**Next steps:**
1. Commit the team-config.md and remediation-tracker.md files
2. Run `/security-review` to conduct your first scan
3. If you have existing pentest reports, place them in `external/pentests/`
4. Set SECURITY_SLACK_WEBHOOK environment variable if using Slack

**For team members:**
- They will get the configuration automatically when pulling
- They should set the SECURITY_SLACK_WEBHOOK env var if using Slack notifications"

## Reconfiguration

If user is reconfiguring (existing config found):
- Show current settings
- Allow selective updates
- Preserve existing data (reports, tracker entries)
- Update only changed settings
