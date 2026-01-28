---
name: Security Context
description: This skill should be used when the user asks to "review security", "check for vulnerabilities", "security audit", "find security issues", "pentest remediation", "check compliance", "SOC II review", "GDPR compliance", or mentions security-related terms like "OWASP", "injection", "XSS", "authentication vulnerabilities", "hardcoded secrets". Provides stack-specific security context, compliance guidance, and historical audit trail awareness.
version: 1.0.0
---

# Security Context Skill

This skill provides comprehensive security review context tailored to the project's specific technology stack, compliance requirements, and security history.

## Overview

When activated, this skill:

1. Loads the team's security configuration
2. Injects stack-specific security rules (FastAPI, Next.js, Supabase, etc.)
3. Applies relevant compliance guidance (SOC II, GDPR, etc.)
4. References recent security scan reports for historical context
5. Checks the remediation tracker for open/in-progress issues

## Configuration Loading

Before any security review, load the team configuration:

1. Read `{security_path}/team-config.md` for project settings
2. Extract the `stacks` array to determine which stack rules to load
3. Extract the `compliance` array to determine compliance context
4. Note the `past_reports_count` setting (default: 3)

If no configuration exists, prompt to run `/security-setup` first.

## Stack-Specific Context

Based on the configured stacks, load relevant security rules from `references/stacks/`:

| Stack | Reference File | Key Concerns |
|-------|---------------|--------------|
| FastAPI | `fastapi.md` | Async vulnerabilities, Pydantic validation, dependency injection |
| Next.js | `nextjs.md` | SSR/CSR security, API routes, middleware, environment exposure |
| Supabase | `supabase.md` | RLS policies, auth configuration, storage security |
| Qdrant | `qdrant.md` | Vector DB access control, API security |

For unlisted stacks, use `_template.md` as guidance for what to check.

## Compliance Context

Based on configured compliance targets, load from `references/compliance/`:

| Target | Reference File | Focus Areas |
|--------|---------------|-------------|
| SOC II | `soc2.md` | Access control, encryption, logging, change management |
| GDPR | `gdpr.md` | Data handling, consent, subject rights, breach notification |
| Pentest | `pentest-guidance.md` | Common findings, remediation patterns |

## Universal Security Checks

Always load `references/universal/owasp-top-10.md` which covers:

- **Injection** - SQL, command, LDAP, XPath, NoSQL, XXE
- **Broken Authentication** - Session management, credential handling
- **Sensitive Data Exposure** - Encryption, PII, secrets
- **XXE** - XML external entity attacks
- **Broken Access Control** - Authorization, IDOR, privilege escalation
- **Security Misconfiguration** - Headers, CORS, defaults
- **XSS** - Reflected, stored, DOM-based
- **Insecure Deserialization** - Object injection, RCE
- **Vulnerable Components** - Dependencies, supply chain
- **Insufficient Logging** - Audit trails, monitoring

## Historical Context

To understand the project's security journey:

1. Read the last N reports from `{reports_path}/` (N = `past_reports_count`)
2. Read `{remediation_tracker}` to understand:
   - Open findings requiring attention
   - In-progress remediation work
   - Recently fixed issues (to verify fixes)
   - Accepted risks (to avoid re-flagging)

3. Read any external reports from `{external_path}/`:
   - `pentests/` - Third-party pentest findings
   - `compliance/` - Audit reports, compliance assessments

This historical context helps:
- Avoid duplicate findings
- Track remediation progress
- Understand recurring patterns
- Respect accepted risk decisions

## Review Areas

When conducting reviews, organize findings by area:

| Area | What to Check |
|------|---------------|
| `auth` | Authentication flows, session management, authorization, IDOR, privilege escalation |
| `injection` | SQL, command, LDAP, XPath, NoSQL, XXE injection points |
| `secrets` | Hardcoded credentials, API keys, PII exposure, logging sensitive data |
| `crypto` | Algorithm strength, key management, random number generation |
| `validation` | Input sanitization, type checking, boundary validation |
| `logic` | Race conditions, TOCTOU, business logic flaws |
| `config` | Security headers, CORS policy, secure defaults |
| `deps` | Known CVEs in dependencies, outdated packages |
| `rce` | Deserialization, eval/exec usage, template injection |
| `xss` | Output encoding, CSP, DOM manipulation |

## Report Format

When saving reports, use this structure:

```markdown
# Security Review Report

**Date:** YYYY-MM-DD
**Type:** [full | targeted: {area}]
**Reviewer:** Claude (security-review plugin)

## Summary

- **Critical:** X findings
- **High:** X findings
- **Medium:** X findings
- **Low:** X findings

## Findings

### [SEVERITY] Finding Title

**Area:** {area}
**Location:** `file/path.py:123`
**Status:** Open

**Description:**
What the vulnerability is and why it matters.

**Evidence:**
```code
vulnerable code snippet
```

**Remediation:**
How to fix it with example.

**References:**
- OWASP link
- CWE link

---

## Recommendations

Prioritized list of next steps.
```

## Remediation Tracker Format

The remediation tracker (`remediation-tracker.md`) uses this format:

```markdown
# Security Remediation Tracker

Last Updated: YYYY-MM-DD

## Open Findings

| ID | Severity | Area | Description | Found | Owner |
|----|----------|------|-------------|-------|-------|
| SEC-001 | Critical | auth | JWT not validated | 2026-01-15 | @dev |

## In Progress

| ID | Severity | Area | Description | Started | Owner | PR |
|----|----------|------|-------------|---------|-------|-----|
| SEC-002 | High | injection | SQL injection in search | 2026-01-20 | @dev | #123 |

## Fixed

| ID | Severity | Area | Description | Fixed | Verified |
|----|----------|------|-------------|-------|----------|
| SEC-003 | Medium | config | Missing HSTS header | 2026-01-22 | Yes |

## Accepted Risk

| ID | Severity | Area | Description | Reason | Approved By |
|----|----------|------|-------------|--------|-------------|
| SEC-004 | Low | deps | Lodash prototype pollution | Not exploitable in our usage | @security-lead |
```

## Slack Notification

When Slack is configured, notifications include:

1. **Summary line** - Total findings by severity
2. **Key findings** - Critical and high severity items
3. **Report attachment** - Full markdown report (if `slack_include_full_report: true`)
4. **Link** - Path to full report in repo

## Additional Resources

### Stack-Specific Rules
- **`references/stacks/fastapi.md`** - FastAPI/Python security patterns
- **`references/stacks/nextjs.md`** - Next.js/React security patterns
- **`references/stacks/supabase.md`** - Supabase security configuration
- **`references/stacks/qdrant.md`** - Vector database security
- **`references/stacks/_template.md`** - Template for adding new stacks

### Compliance Guidance
- **`references/compliance/soc2.md`** - SOC II Trust Service Criteria
- **`references/compliance/gdpr.md`** - GDPR requirements checklist
- **`references/compliance/pentest-guidance.md`** - Pentest remediation patterns

### Universal Security
- **`references/universal/owasp-top-10.md`** - OWASP Top 10 detailed guidance

### Examples
- **`examples/`** - Vulnerable vs. fixed code examples by category
