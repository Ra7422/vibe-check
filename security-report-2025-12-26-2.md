# Security Scan Report

**Repository:** https://github.com/Ra7422/meedi8
**Score:** 0/100
**Date:** 2025-12-26

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 16 |
| Medium | 4 |
| Low | 8 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:545`

---

### 2. [MEDIUM] HTTP URLs

**Category:** Configuration

**Description:** HTTP URLs are insecure. Data can be intercepted.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:111`

---

### 3. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:104`

---

### 4. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:149`

---

### 5. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:943`

---

### 6. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:944`

---

### 7. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:945`

---

### 8. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:946`

---

### 9. [LOW] Hardcoded IP Address

**Category:** Configuration

**Description:** Hardcoded IP address found. This reduces flexibility.

**Location:** `backend/DEMOGRAPHIC_DATA_DESIGN.md:947`

---

### 10. [CRITICAL] Database URL with Credentials

**Category:** Secrets

**Description:** Database connection string with credentials detected.

**Location:** `backend/RAILWAY_DEPLOYMENT_FIX.md:32`

---

### 11. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/main.py:230`

---

### 12. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:705`

---

### 13. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:707`

---

### 14. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:734`

---

### 15. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:736`

---

### 16. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:792`

---

### 17. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/routes/telegram.py:793`

---

### 18. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:527`

---

### 19. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:529`

---

### 20. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:531`

---

### 21. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:588`

---

### 22. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:590`

---

### 23. [HIGH] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection vulnerability. User input may be concatenated into queries.

**Location:** `backend/app/services/citation_extractor.py:592`

---

### 24. [CRITICAL] [AI] Hardcoded Secrets

**Category:** Secrets Management

**Description:** The configuration file contains several hardcoded secrets, including API keys, client IDs, and client secrets. These secrets should not be hardcoded in the codebase and should be managed securely, such as through environment variables or a secrets management service.

**Location:** `backend/app/config.py`

---

### 25. [CRITICAL] [AI] Hardcoded Secret Key

**Category:** Hardcoded Secrets

**Description:** The `SECRET_KEY` is hardcoded to `dev-secret-change-me`. This is a major security vulnerability as it can be used to sign and verify JWTs, potentially allowing attackers to forge user identities and bypass authentication.

**Location:** `backend/app/config.py:7`

---

### 26. [HIGH] [AI] Hardcoded API Key in Configuration

**Category:** Hardcoded Secrets

**Description:** The API key is hardcoded in the configuration file, which poses a security risk if the application is deployed publicly.

**Location:** `backend/app/deps.py:8`

---

### 27. [HIGH] [AI] Potential JWT Algorithm Confusion Vulnerability

**Category:** Authentication

**Description:** The JWT decoding uses a single algorithm specified in settings.ALGORITHM. If this is not properly validated or if the algorithm can be influenced by user input, it could lead to algorithm confusion attacks where an attacker can use a weaker algorithm to sign tokens.

**Location:** `backend/app/deps.py:23`

---

### 28. [MEDIUM] [AI] Insecure Exception Handling in get_current_user_optional

**Category:** Error Handling

**Description:** The get_current_user_optional function catches all exceptions with a bare except clause, which could mask unexpected errors and make debugging difficult. This could potentially hide security-related exceptions.

**Location:** `backend/app/deps.py:80`

---

### 29. [MEDIUM] [AI] Hardcoded Sentry DSN in Configuration

**Category:** Hardcoded Secrets

**Description:** The Sentry DSN (Data Source Name) is hardcoded in the configuration, which could potentially expose sensitive information if the application is compromised.

**Location:** `backend/app/main.py:45`

---

### 30. [MEDIUM] [AI] Insecure exception handling

**Category:** exception_handling

**Description:** The middleware has an empty catch block that logs an error message but does not handle the exception properly. This can lead to unexpected behavior or data loss.

**Location:** `backend/app/middleware/activity_tracker.py:32`

---

### 31. [LOW] Partial Scan

**Category:** Info

**Description:** Repository has 746 scannable files. Only first 100 were scanned to avoid timeout.

---

