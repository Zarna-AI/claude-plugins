---
description: Set up or reconfigure the security review plugin for your project
allowed-tools: Read, Glob, Grep, Bash(ls:*, test:*, mkdir:*, which:*, find:*, chmod:*, cp:*, cat:*), Write, AskUserQuestion
---

# Security Review Plugin Setup

Configure the security review plugin for this project. This creates the team configuration, directory structure, and git hooks for commit-time security tracking.

**This setup is idempotent** - it will skip steps that are already complete.

## Step 1: Check Existing Configuration

Search for existing configuration:
- `**/security/team-config.md`
- `**/zz_plans/security/team-config.md`

**If found:**
- Show: "✓ Team configuration already exists at [path]"
- Ask: "Would you like to reconfigure or keep existing settings?"
- If keeping existing, skip to Step 7 (hook installation)

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

**Check if directories already exist before creating:**

```bash
test -d "{security_path}" && echo "✓ Security directory exists" || mkdir -p "{security_path}"
test -d "{security_path}/reports" && echo "✓ Reports directory exists" || mkdir -p "{security_path}/reports"
test -d "{security_path}/external/pentests" && echo "✓ External pentests directory exists" || mkdir -p "{security_path}/external/pentests"
test -d "{security_path}/external/compliance" && echo "✓ External compliance directory exists" || mkdir -p "{security_path}/external/compliance"
```

Target structure:
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

**Check if team-config.md already exists:**

```bash
test -f "{security_path}/team-config.md" && echo "exists"
```

If exists → Show "✓ team-config.md already exists" and skip creation (unless reconfiguring).

If creating, write `{security_path}/team-config.md`:

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

**Check if remediation-tracker.md already exists:**

```bash
test -f "{security_path}/remediation-tracker.md" && echo "exists"
```

If exists → Show "✓ remediation-tracker.md already exists" and skip creation.

If creating, write `{security_path}/remediation-tracker.md`:

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

## Step 10: Install Git Hooks

Install pre-commit and post-commit hooks to track security scan status.

### 10a: Find Git Repositories

```bash
find . -name ".git" -type d -maxdepth 3 2>/dev/null | sed 's/\/.git$//'
```

This returns paths like:
- `./zarna-frontend`
- `./zarna-backend`

### 10b: Check Existing Hooks

For each git repository found, check if hooks already exist:

```bash
test -f "{repo}/.git/hooks/pre-commit" && echo "pre-commit exists"
test -f "{repo}/.git/hooks/post-commit" && echo "post-commit exists"
```

If hooks exist, check if they're ours (contain "security-scan" marker):
```bash
grep -q "# security-scan-hook" "{repo}/.git/hooks/pre-commit" && echo "our hook"
```

**If our hooks already installed:** Show "✓ Git hooks already installed in {repo}" and skip.

**If other hooks exist:** Ask user if they want to append or skip.

### 10c: Create State File

Create `.security-state` at project root if it doesn't exist:

```yaml
# .security-state
# Tracks security scan status across commits
# DO NOT COMMIT - add to .gitignore

last_scan:
  timestamp: null
  report: null
  repos: {}

unscanned_commits:
  # Files committed without prior security scan
  # Cleared when scan runs
```

### 10d: Install Pre-commit Hook

For each repository, create `{repo}/.git/hooks/pre-commit`:

```bash
#!/bin/bash
# security-scan-hook: pre-commit
# Warns if committing files that weren't security scanned

STATE_FILE="$(git rev-parse --show-toplevel)/../.security-state"
REPO_NAME=$(basename "$(git rev-parse --show-toplevel)")

# Get staged files (excluding deletions)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=d)

if [ -z "$STAGED_FILES" ]; then
    exit 0  # No files staged
fi

# Check if state file exists
if [ ! -f "$STATE_FILE" ]; then
    echo ""
    echo "⚠️  SECURITY SCAN RECOMMENDED"
    echo "   No security scan record found."
    echo "   Run: /security-scan:scan"
    echo ""
    echo "   Proceeding with commit..."
    echo ""
    exit 0  # Warning only, don't block
fi

# Check if files were scanned (using grep for simplicity)
UNSCANNED=""
for FILE in $STAGED_FILES; do
    if ! grep -q "$FILE" "$STATE_FILE" 2>/dev/null; then
        UNSCANNED="$UNSCANNED\n   - $FILE"
    fi
done

if [ -n "$UNSCANNED" ]; then
    echo ""
    echo "⚠️  SECURITY SCAN RECOMMENDED"
    echo "   The following files were not in the last security scan:"
    echo -e "$UNSCANNED"
    echo ""
    echo "   Run: /security-scan:scan"
    echo "   Or commit anyway (files will be tracked for next scan)"
    echo ""
fi

exit 0  # Warning only, don't block commits
```

Make executable: `chmod +x {repo}/.git/hooks/pre-commit`

### 10e: Install Post-commit Hook

For each repository, create `{repo}/.git/hooks/post-commit`:

```bash
#!/bin/bash
# security-scan-hook: post-commit
# Tracks files committed without security scan

STATE_FILE="$(git rev-parse --show-toplevel)/../.security-state"
REPO_NAME=$(basename "$(git rev-parse --show-toplevel)")

# Get files from the commit we just made
COMMITTED_FILES=$(git diff-tree --no-commit-id --name-only -r HEAD)

if [ -z "$COMMITTED_FILES" ]; then
    exit 0
fi

# Ensure state file exists
if [ ! -f "$STATE_FILE" ]; then
    cat > "$STATE_FILE" << 'YAML'
# .security-state
last_scan:
  timestamp: null
  report: null
  repos: {}
unscanned_commits: {}
YAML
fi

# Check which files were NOT in last scan and add to unscanned_commits
for FILE in $COMMITTED_FILES; do
    if ! grep -q "$FILE" "$STATE_FILE" 2>/dev/null; then
        # Add to unscanned list if not already there (deduplication)
        if ! grep -q "^  - $REPO_NAME/$FILE$" "$STATE_FILE" 2>/dev/null; then
            # Append to unscanned_commits section
            # Using a simple marker-based approach
            sed -i.bak "/^unscanned_commits:/a\\
\\ \\ $REPO_NAME:\\
\\ \\ \\ \\ - $FILE" "$STATE_FILE" 2>/dev/null || true
        fi
    fi
done

# Clear this repo from last_scan.repos (scan is now stale for committed files)
# The scan.md command will rebuild this when run

exit 0
```

Make executable: `chmod +x {repo}/.git/hooks/post-commit`

### 10f: Update .gitignore

Check if `.security-state` is in `.gitignore`:

```bash
grep -q "\.security-state" .gitignore && echo "already ignored"
```

If not present, append:
```
# Security scan tracking (local only)
.security-state
```

### 10g: Report Installation Status

For each repo, report:
- "✓ Installed pre-commit hook in {repo}"
- "✓ Installed post-commit hook in {repo}"
- Or "✓ Hooks already installed in {repo}" if skipped

## Step 11: Summary and Next Steps

Present summary:

"Security review plugin configured successfully!

**Configuration:**
- Path: [security_path]
- Stacks: [list]
- Compliance: [list]
- Slack: [configured/not configured]

**Created/verified:**
- ✓ [security_path]/team-config.md
- ✓ [security_path]/remediation-tracker.md
- ✓ [security_path]/reports/ (directory)
- ✓ [security_path]/external/pentests/ (directory)
- ✓ [security_path]/external/compliance/ (directory)
- ✓ .security-state (local tracking file)
- ✓ Git hooks installed in [list repos]

**Git Hook Behavior:**
- **Pre-commit:** Warns if files weren't security scanned (non-blocking)
- **Post-commit:** Tracks files committed without scan for next review
- **After scan:** Clears tracking, fresh start

**Next steps:**
1. Commit the team-config.md and remediation-tracker.md files
2. Run `/security-scan:scan` to conduct your first scan
3. If you have existing pentest reports, place them in `external/pentests/`
4. Set SECURITY_SLACK_WEBHOOK environment variable if using Slack

**For team members:**
- Run `/security-scan:setup` once to install git hooks locally
- They will get the configuration (team-config.md) automatically when pulling
- Git hooks must be installed per-machine (not shared via git)"

## Reconfiguration

If user is reconfiguring (existing config found):
- Show current settings
- Allow selective updates
- Preserve existing data (reports, tracker entries)
- Update only changed settings
