# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 43/100
**Date:** 2025-12-23

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 2 |
| Low | 1 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [CRITICAL] Potential Hardcoded Secret Detected

**Category:** Secrets

**Description:** The scanner found patterns that may indicate hardcoded credentials or API keys in your code.

**Location:** `src/config.ts:15`

---

### 2. [HIGH] Missing Rate Limiting

**Category:** API Security

**Description:** API endpoints do not appear to have rate limiting configured, which could allow abuse.

---

### 3. [HIGH] Dependencies May Be Outdated

**Category:** Dependencies

**Description:** Some packages may have known security vulnerabilities.

---

### 4. [MEDIUM] Missing Content Security Policy

**Category:** Headers

**Description:** No Content-Security-Policy header detected. This helps prevent XSS attacks.

---

### 5. [MEDIUM] Debug Mode May Be Enabled

**Category:** Configuration

**Description:** Debug settings may be enabled which could expose sensitive information.

---

### 6. [LOW] Console Logs Found

**Category:** Best Practice

**Description:** Multiple console.log statements found which may leak information.

---

