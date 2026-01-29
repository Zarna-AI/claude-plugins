---
description: Run enhanced security review with stack-specific context and compliance tracking
argument-hint: [--area <area>] [--no-save] [--no-slack]
allowed-tools: Read, Glob, Grep, Bash, Write, Skill
---

# Enhanced Security Review

This command enhances Claude's built-in security review with project-specific context:
- Stack-specific vulnerability patterns (FastAPI, Next.js, Supabase, etc.)
- Compliance requirements (SOC 2, GDPR, ISO 27001)
- Known issues from pentests, past scans, and remediation tracker

The result is a comprehensive security report that:
1. **Finds NEW vulnerabilities** not previously identified
2. **Highlights unresolved known issues** as reminders (without re-scanning them)
3. **Tracks remediation progress** by checking if known issues have been fixed

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

## Step 6: Run Security Review with Loaded Context

Now that all context is loaded, perform Claude's built-in security review enhanced with the project-specific context.

### 6a. Prepare Context Summary

Before running the review, summarize what you've loaded:

```
CONTEXT LOADED FOR SECURITY REVIEW:
- Stack patterns: {list technologies}
- Compliance frameworks: {list frameworks}
- Known issues to skip: {count from remediation tracker + external assessments}
- Past scan reports reviewed: {count}
```

### 6b. Build Known Issues List

From all loaded context, build a list of known issues:

| Source | Issues | Action |
|--------|--------|--------|
| Remediation Tracker - Open | {list IDs and descriptions} | Don't re-scan, but HIGHLIGHT in report as unresolved |
| Remediation Tracker - In Progress | {list IDs and descriptions} | Don't re-scan, but HIGHLIGHT in report as unresolved |
| Remediation Tracker - Accepted Risk | {list IDs and descriptions} | Don't re-scan, don't highlight (team accepted) |
| External Pentests | {list findings} | Don't re-scan, but HIGHLIGHT in report as unresolved |
| External Compliance Audits | {list findings} | Don't re-scan, but HIGHLIGHT in report as unresolved |

**Key distinction:**
- **Don't re-scan** = Don't spend time looking for these issues again
- **Highlight in report** = Include them in the "Unresolved Known Issues" section as reminders

### 6c. Invoke Built-in Security Review

Use the **Skill tool** to invoke Claude's built-in `/security-review` command:

```
Skill: security-review
```

The built-in command will run with all the context you've loaded (stack patterns, compliance requirements, known issues) available in the conversation.

**IMPORTANT:** Before invoking, remind yourself of the context:

> I have loaded the following context for this security review:
> - Stack patterns: {list from Step 3}
> - Compliance requirements: {list from Step 4}
> - Known issues to skip (but highlight as reminders): {count from Step 5}
>
> When running the security review:
> 1. Apply the stack-specific vulnerability patterns I loaded
> 2. Check compliance requirements I loaded
> 3. Don't re-report known issues, but include them in "Unresolved Known Issues" section
> 4. Focus on finding NEW vulnerabilities

Then invoke: `Skill tool with skill: "security-review"`

### 6d. Enhance Results with Loaded Context

After the built-in security review completes, enhance the results:

1. **Cross-reference findings** with known issues list
   - If a finding matches a known issue → Note it's already tracked (don't duplicate)
   - If a finding is NEW → Keep it in the new findings section

2. **Add compliance mapping** to each finding
   - Which compliance frameworks are affected (SOC 2, GDPR, ISO 27001)?

3. **Add stack-specific remediation** guidance from loaded patterns

**For each NEW finding, record:**
- Severity (Critical/High/Medium/Low/Info)
- Area (auth, injection, secrets, crypto, validation, logic, config, deps, rce, xss)
- Location (file:line)
- Description
- Evidence (code snippet)
- Remediation steps
- Compliance implications (if any)

### 6e. Update Remediation Tracker

After completing the review:

1. **Add NEW findings** to "Open Findings" in `{security_path}/remediation-tracker.md`
   - Generate IDs as `SEC-{YEAR}-{NNN}` (increment from last ID)
   - Set Found date to today
   - Leave Owner blank

2. **Check if Open issues are now fixed:**
   - For each issue in "Open Findings", check if the vulnerability still exists
   - If FIXED → Move to "Fixed" table with today's date, Verified = Yes

3. **Check if In Progress issues are complete:**
   - For each issue in "In Progress", verify if fix is deployed
   - If FIXED → Move to "Fixed" table

### 6f. Save Report

Save the security review report to: `{reports_path}/YYYY-MM-DD-scan.md`

**Report Format:**

```markdown
# Security Scan Report

**Date:** {today}
**Type:** {full | targeted: <area>}
**Context Used:** {count} stack patterns, {count} compliance frameworks, {count} known issues skipped

## Executive Summary

{2-3 sentences on findings}

## Overall Status

| Category | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| NEW (this scan) | X | X | X | X | X | X |
| Known (not re-reported) | X | X | X | X | X | X |
| **Total Open** | X | X | X | X | X | X |

## New Findings

### Critical

#### {Title}
- **ID:** SEC-YYYY-NNN
- **Location:** `file:line`
- **Description:** ...
- **Evidence:** ```code```
- **Remediation:** ...
- **Compliance:** {affected frameworks}

[Repeat for each finding by severity]

## Unresolved Known Issues (Reminder)

These issues were previously identified and remain unresolved. They are listed here as a reminder - not re-scanned.

### From Internal Scans

| ID | Severity | Area | Description | Days Open | Owner |
|----|----------|------|-------------|-----------|-------|
| {from remediation tracker Open + In Progress} |

### From External Assessments

| Source | ID | Severity | Description | Status |
|--------|-----|----------|-------------|--------|
| {from pentest/audit reports} |

**Priority Reminder:** {Call out any critical/high issues that have been open > 7 days}

## Issues Auto-Fixed

{List any issues moved from Open/In Progress to Fixed}

## Compliance Summary

### {Framework}
- New gaps: {list or "None"}
- Known gaps (not re-reported): {count}

## Areas Verified Clean

{List areas scanned with no new findings}
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
