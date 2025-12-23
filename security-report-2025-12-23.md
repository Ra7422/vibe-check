# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 0/100
**Date:** 2025-12-23

## Summary

| Severity | Count |
|----------|-------|
| Critical | 30 |
| High | 9 |
| Medium | 3 |
| Low | 3 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [HIGH] Eval Usage

**Category:** Code Execution

**Description:** eval() executes arbitrary code and is a major security risk.

**Location:** `run_scan.py:54`

---

### 2. [MEDIUM] HTTP URLs

**Category:** Configuration

**Description:** HTTP URLs are insecure. Data can be intercepted.

**Location:** `run_scan.py:63`

---

### 3. [MEDIUM] TODO Security Comment

**Category:** Technical Debt

**Description:** Unresolved security-related TODO comment found.

**Location:** `run_scan.py:86`

---

### 4. [MEDIUM] TODO Security Comment

**Category:** Technical Debt

**Description:** Unresolved security-related TODO comment found.

**Location:** `run_scan.py:87`

---

### 5. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/flow-check/route.ts:63`

---

### 6. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/flow-check/route.ts:79`

---

### 7. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/flow-check/route.ts:106`

---

### 8. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/flow-check/route.ts:137`

---

### 9. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/flow-check/route.ts:176`

---

### 10. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:63`

---

### 11. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:79`

---

### 12. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:88`

---

### 13. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:96`

---

### 14. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:106`

---

### 15. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:129`

---

### 16. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:137`

---

### 17. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:153`

---

### 18. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:163`

---

### 19. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/flow-check/route.ts:176`

---

### 20. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/api/flow-check/route.ts:245`

---

### 21. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/scan/route.ts:364`

---

### 22. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/scan/route.ts:382`

---

### 23. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `web-app/app/api/scan/route.ts:407`

---

### 24. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:353`

---

### 25. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:364`

---

### 26. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:372`

---

### 27. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:382`

---

### 28. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:407`

---

### 29. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:407`

---

### 30. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:526`

---

### 31. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:558`

---

### 32. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:561`

---

### 33. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/api/scan/route.ts:562`

---

### 34. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/api/scan/route.ts:608`

---

### 35. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:85`

---

### 36. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:86`

---

### 37. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:87`

---

### 38. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:92`

---

### 39. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:93`

---

### 40. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:94`

---

### 41. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:95`

---

### 42. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:101`

---

### 43. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:102`

---

### 44. [CRITICAL] Command Injection Risk

**Category:** Injection

**Description:** Potential command injection. User input may be passed to shell commands.

**Location:** `web-app/app/page.tsx:103`

---

### 45. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/page.tsx:295`

---

