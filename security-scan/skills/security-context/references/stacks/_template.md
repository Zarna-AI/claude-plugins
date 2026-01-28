# [Stack Name] Security Reference

Security patterns and common vulnerabilities specific to [Stack Name].

---

## Overview

Brief description of the technology and its security model.

---

## Authentication & Authorization

### Common Patterns

```code
// Example secure authentication pattern
```

### Vulnerabilities to Check

- [ ] Item 1
- [ ] Item 2

---

## Input Validation

### Secure Patterns

```code
// Example input validation
```

### Common Mistakes

```code
// Vulnerable pattern
```

---

## Data Security

### Encryption

- At rest:
- In transit:

### Sensitive Data Handling

- [ ] Check for hardcoded secrets
- [ ] Check for logging sensitive data

---

## Configuration Security

### Secure Defaults

```code
// Secure configuration example
```

### Common Misconfigurations

- [ ] Misconfiguration 1
- [ ] Misconfiguration 2

---

## Injection Prevention

### SQL/NoSQL/Command Injection

```code
// Safe patterns
```

---

## Stack-Specific Vulnerabilities

### Vulnerability Category 1

Description and remediation.

### Vulnerability Category 2

Description and remediation.

---

## Files to Check

| File/Pattern | What to Look For |
|--------------|------------------|
| `example.config` | Configuration issues |
| `src/**/*.ts` | Code patterns |

---

## Security Checklist

- [ ] Authentication properly implemented
- [ ] Authorization checked on all endpoints
- [ ] Input validated
- [ ] Secrets not hardcoded
- [ ] Dependencies up to date
- [ ] Logging configured (no sensitive data)
- [ ] Error handling doesn't leak info

---

## Additional Resources

- [Official Security Docs](https://example.com/security)
- [OWASP Guide for Stack](https://owasp.org)
