---
description: Run enhanced security review with stack-specific context and compliance tracking
argument-hint: [--area <area>] [--no-save] [--no-slack]
allowed-tools: Read, Glob, Grep, Bash, Write, Task
---

# Enhanced Security Review

This command loads all security context and invokes the security-scanner agent to find NEW vulnerabilities.

## Step 1: Parse Arguments

Parse: $ARGUMENTS

- `--area <name>` - Focus on specific area (auth, injection, secrets, crypto, validation, logic, config, deps, rce, xss)
- `--no-save` - Skip saving report
- `--no-slack` - Skip Slack notification

## Step 2: Load Team Configuration

```
Glob: **/security/team-config.md
```

If not found → tell user to run `/security-setup` first and STOP.

Extract from YAML frontmatter:
- `stacks` - Technologies list
- `compliance` - Compliance frameworks
- `security_path` - Base directory
- `reports_path` - Where reports go
- `external_path` - External assessments location
- `past_reports_count` - How many past reports to load (default: 3)

## Step 3: Load Stack-Specific Patterns

For EACH technology in `stacks`, read the matching reference file:

| If stacks contains | Read |
|-------------------|------|
| FastAPI, Python, fastapi | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/stacks/fastapi.md` |
| Next.js, Next, nextjs, React | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/stacks/nextjs.md` |
| Supabase, supabase | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/stacks/supabase.md` |
| Qdrant, qdrant | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/stacks/qdrant.md` |

Concatenate all content → `STACK_PATTERNS`

## Step 4: Load Compliance Requirements

For EACH framework in `compliance`, read:

| If compliance contains | Read |
|-----------------------|------|
| SOC II, SOC2, soc2 | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/compliance/soc2.md` |
| GDPR, gdpr | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/compliance/gdpr.md` |
| ISO, ISO 27001, iso27001 | `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/compliance/iso27001.md` |

Always also read:
- `${CLAUDE_PLUGIN_ROOT}/skills/security-context/references/universal/owasp-top-10.md`

Concatenate all content → `COMPLIANCE_REQUIREMENTS`

## Step 5: Load Known Issues

This is critical - we need to tell the scanner what's ALREADY KNOWN so it doesn't waste time re-finding these.

### 5a. Past Security Scan Reports

```
Glob: {reports_path}/*.md
```

Read the most recent N files (N = past_reports_count). Extract findings sections.

→ `PAST_SCAN_FINDINGS`

### 5b. Remediation Tracker

```
Read: {security_path}/remediation-tracker.md
```

Extract:
- Open findings (already known, don't re-report)
- In-progress findings (being worked on)
- Accepted risks (team decision, never re-flag)
- Fixed findings (optionally verify)

→ `REMEDIATION_STATUS`

### 5c. External Assessments (Pentests, Audits, Compliance Reports)

```
Glob: {external_path}/pentests/*
Glob: {external_path}/compliance/*
```

Read ALL files found. These contain findings from:
- Third-party penetration tests
- SOC II audits
- GDPR assessments
- ISO 27001 audits
- Any other external security reviews

→ `EXTERNAL_FINDINGS`

## Step 6: Invoke Security Scanner Agent

Use Task tool with `subagent_type: security-scan:security-scanner`

**Build the prompt with ALL loaded context:**

```
# Security Scan Request

## Your Mission
Find NEW security vulnerabilities. We're providing you with everything that's already known - don't re-report those. Focus your efforts on discovering issues that haven't been found yet.

## Scan Configuration
- Type: {full | targeted: <area>}
- Save report to: {reports_path}
- Date: {current date}

---

## KNOWN ISSUES - DO NOT RE-REPORT THESE

The following issues are already tracked. Skip them and focus on finding NEW problems.

### From Remediation Tracker

{REMEDIATION_STATUS}

**Instructions:**
- "Open" items → Already known, don't re-report
- "In Progress" items → Being fixed, don't re-report
- "Accepted Risk" items → Team decision, NEVER flag these
- "Fixed" items → Can optionally verify fix is solid

### From Past Security Scans

{PAST_SCAN_FINDINGS}

### From External Assessments (Pentests, Audits)

{EXTERNAL_FINDINGS}

---

## STACK-SPECIFIC PATTERNS TO USE

Use these patterns when scanning. They're tailored to this project's tech stack:

{STACK_PATTERNS}

---

## COMPLIANCE REQUIREMENTS TO CHECK

Check for NEW gaps against these requirements (skip gaps already in known issues):

{COMPLIANCE_REQUIREMENTS}

---

## Instructions

1. Build a "skip list" from all known issues above
2. Scan the codebase systematically
3. Use the stack-specific patterns provided
4. Check compliance requirements for NEW gaps
5. Report only NEW findings
6. **AUTO-UPDATE TRACKER:**
   - Add NEW findings to "Open Findings" in remediation-tracker.md
   - Check if "Open" issues are now fixed → move to "Fixed"
   - Check if "In Progress" issues are complete → move to "Fixed"
   - Generate IDs as SEC-{YEAR}-{NNN}
7. In your report, show:
   - NEW findings discovered
   - Known issues still open (not re-scanned, just status)
   - Issues that were auto-moved to Fixed
8. Save report to: {reports_path}/YYYY-MM-DD-scan.md
9. Save updated tracker to: {security_path}/remediation-tracker.md
```

## Step 7: Post-Scan Actions

After agent completes:

### Verify Report Saved
Check that `{reports_path}/YYYY-MM-DD-scan.md` exists.

### Slack Notification (unless --no-slack)

If configured:

1. Source .envrc to get SECURITY_SLACK_WEBHOOK
2. Format message (plain text only):
   ```
   Security Scan Complete - {date}

   NEW Findings: {critical} Critical, {high} High, {medium} Medium, {low} Low
   Issues Remediated: {count} (auto-moved to Fixed)
   Total Open: {count}

   Top issues:
   - {issue 1}
   - {issue 2}

   Report: {report_path}
   ```

3. Send:
   ```bash
   source /path/to/.envrc 2>/dev/null
   curl -s -X POST -H 'Content-type: application/json' \
     -d '{"text":"<message>"}' "$SECURITY_SLACK_WEBHOOK"
   ```

### Update Config
Update `last_scan` date in team-config.md.

## Output

Present to user:
1. NEW findings count by severity
2. Tracker updates:
   - Issues added to Open: X
   - Issues auto-moved to Fixed: X (they're now remediated!)
   - Issues still open from before: X
3. Total open issues (new + existing)
4. Top 3 critical/high issues (new or still open)
5. Report location
6. Slack notification status
