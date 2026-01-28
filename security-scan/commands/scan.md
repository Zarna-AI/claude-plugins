---
description: Run enhanced security review with stack-specific context and compliance tracking
argument-hint: [--area <area>] [--no-save] [--no-slack]
allowed-tools: Read, Glob, Grep, Bash(npm:*, safety:*, gitleaks:*, git:*), Write, Task
---

# Enhanced Security Review

Conduct a comprehensive security review with stack-specific context, compliance requirements, and historical awareness.

## Configuration Loading

First, locate and read the team configuration:

1. Search for `team-config.md` in common security directories:
   - `**/security/team-config.md`
   - `**/zz_plans/security/team-config.md`

2. If found, parse the YAML frontmatter to extract:
   - `stacks` - Technologies to load rules for
   - `compliance` - Compliance frameworks to consider
   - `reports_path` - Where to save reports
   - `external_path` - Where external reports are stored
   - `past_reports_count` - How many past reports to reference
   - `slack_webhook` - Notification endpoint

3. If no configuration found, inform user to run `/security-setup` first.

## Arguments

Parse the provided arguments: $ARGUMENTS

- `--area <name>` - Focus on specific area instead of full review
  - Valid areas: auth, injection, secrets, crypto, validation, logic, config, deps, rce, xss
- `--no-save` - Skip saving report to file (by default, reports are saved)
- `--no-slack` - Skip Slack notification even if configured

If no area specified, conduct full review covering all areas.

## Context Loading

Based on configuration, load relevant context from the skill's references:

### Stack-Specific Rules
For each stack in the configuration, the security-context skill provides detailed security patterns. Reference these when reviewing code for that technology.

### Compliance Context
For each compliance target (soc2, gdpr), the skill provides specific requirements to check.

### Historical Context
1. Read the last N reports from `{reports_path}/` (N = past_reports_count, default 3)
2. Read `{remediation_tracker}` if it exists to understand:
   - Open findings to verify still exist
   - In-progress work to check status
   - Recently fixed items to verify
   - Accepted risks to not re-flag

3. Check `{external_path}/` for pentest reports or compliance audits to reference

## Review Process

### For Full Review (no --area)

Systematically review the codebase for all security areas:

1. **Authentication & Authorization (auth)**
   - Login/logout flows
   - Session management
   - JWT/token handling
   - Role-based access control
   - IDOR vulnerabilities

2. **Injection (injection)**
   - SQL injection points
   - Command injection
   - NoSQL injection
   - XXE vulnerabilities
   - LDAP/XPath injection

3. **Secrets & Data Exposure (secrets)**
   - Hardcoded credentials
   - API keys in code
   - Sensitive data in logs
   - PII handling

4. **Cryptography (crypto)**
   - Algorithm strength
   - Key management
   - Random number generation

5. **Input Validation (validation)**
   - Missing validation
   - Improper sanitization
   - Type coercion issues

6. **Business Logic (logic)**
   - Race conditions
   - TOCTOU issues
   - Workflow bypass

7. **Configuration (config)**
   - Security headers
   - CORS configuration
   - Debug mode in production
   - Default credentials

8. **Dependencies (deps)**
   Run dependency checks:
   - For Node.js projects: `npm audit --json` in frontend directories
   - For Python projects: `safety check -r requirements.txt` if safety is installed
   Report any vulnerabilities found.

9. **Remote Code Execution (rce)**
   - Deserialization issues
   - eval/exec usage
   - Template injection

10. **Cross-Site Scripting (xss)**
    - Reflected XSS
    - Stored XSS
    - DOM-based XSS

### For Targeted Review (--area specified)

Focus only on the specified area with deeper analysis.

## Report Generation

Generate a structured report:

```markdown
# Security Review Report

**Date:** [Current date]
**Type:** [full | targeted: {area}]
**Reviewer:** Claude (security-review plugin v1.0.0)

## Summary

- **Critical:** X findings
- **High:** X findings
- **Medium:** X findings
- **Low:** X findings

## Configuration

- **Stacks reviewed:** [list from config]
- **Compliance context:** [list from config]
- **Historical reports referenced:** [count]

## Findings

[For each finding:]

### [SEVERITY] Finding Title

**Area:** {area}
**Location:** `file/path:line`
**Status:** Open

**Description:**
What the vulnerability is and why it matters.

**Evidence:**
```
[code snippet]
```

**Remediation:**
How to fix it with example.

**References:**
- Relevant OWASP/CWE links

---

## Comparison with Previous Scans

[If historical reports were available:]
- New findings since last scan
- Fixed since last scan
- Still open from previous scans

## Recommendations

Prioritized list of next steps.
```

## Saving Report

By default, always save the report (unless `--no-save` is provided):

1. Generate filename: `{reports_path}/YYYY-MM-DD-{type}-scan.md`
2. Write the report to that location
3. Update `last_scan` and `last_scan_type` in team-config.md

If `--no-save` is provided, skip saving and only display findings in chat.

## Slack Notification

If Slack is configured and `--no-slack` not provided:

1. Prepare summary message with:
   - Total findings by severity
   - Critical/High findings details
   - Link to full report location

2. Note: Actual Slack posting requires the slack-notify.sh script or manual action.
   Provide the formatted message for posting.

## Output

Present findings clearly with:
- Severity-sorted list
- Specific file locations and line numbers
- Code snippets showing the issue
- Clear remediation guidance
- References to relevant stack/compliance documentation
