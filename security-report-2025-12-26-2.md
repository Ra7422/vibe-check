# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 90/100
**Date:** 2025-12-26

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 0 |
| Low | 0 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [HIGH] [AI] Hardcoded API Keys in Code

**Category:** Sensitive Information Exposure

**Description:** The code contains hardcoded API keys for various LLM providers, which should not be stored in the codebase. This poses a security risk if the codebase is publicly accessible or shared.

**Location:** `web-app/app/page.tsx:56`

---

