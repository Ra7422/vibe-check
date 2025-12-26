# Security Scan Report

**Repository:** https://github.com/ra7422/vibe-check
**Score:** 43/100
**Date:** 2025-12-26

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 7 |
| Low | 1 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [MEDIUM] [AI] Potential Cross-Site Scripting (XSS) Vulnerability

**Category:** Security

**Description:** The `metadata.description` field could potentially contain user-supplied input, which could lead to a cross-site scripting (XSS) vulnerability if not properly sanitized.

**Location:** `web-app/app/layout.tsx:8`

---

### 2. [MEDIUM] [AI] Sensitive Information Stored in Local Storage

**Category:** Data Storage

**Description:** The code stores the GitHub token and LLM API keys in the browser's local storage. This can be a security vulnerability, as local storage is accessible to JavaScript and can be read by other scripts running on the same domain.

**Location:** `web-app/app/page.tsx:67`

---

### 3. [MEDIUM] [AI] Lack of Input Validation

**Category:** Input Validation

**Description:** The code does not perform any input validation on the repository URL or the API keys. This could lead to security issues, such as code injection or other types of attacks, if the user inputs malicious data.

**Location:** `web-app/app/page.tsx`

---

### 4. [HIGH] [AI] Exposure of GitHub Token

**Category:** Sensitive Data Exposure

**Description:** The GitHub token is stored in localStorage without encryption, which can be accessed by any script running on the same origin, potentially exposing it to malicious actors.

**Location:** `web-app/app/page.tsx:28`

---

### 5. [MEDIUM] [AI] Inadequate Error Handling

**Category:** Error Handling

**Description:** The catch block in the useEffect hook that processes stored API keys does not handle errors properly, which could lead to silent failures in key management.

**Location:** `web-app/app/page.tsx:21`

---

### 6. [LOW] [AI] Sensitive Information Exposure - API Keys in LocalStorage

**Category:** Information Disclosure

**Description:** The application stores LLM API keys (Anthropic, OpenAI, Gemini, Grok, Mistral) in local storage. While localStorage is scoped to the origin, it's still vulnerable to XSS attacks, which could allow an attacker to steal these API keys. These API keys are sensitive credentials that should be protected more carefully, for example by encrypting them before storing or storing them server-side.

**Location:** `web-app/app/page.tsx:40`

---

### 7. [HIGH] [AI] Sensitive Data Exposure in Local Storage

**Category:** Data Protection

**Description:** GitHub tokens and LLM API keys are stored in localStorage, which is vulnerable to XSS attacks. Sensitive credentials should be stored in more secure locations like HttpOnly cookies or secure server-side storage.

**Location:** `web-app/app/page.tsx:25`

---

### 8. [MEDIUM] [AI] Insecure Token Handling

**Category:** Authentication

**Description:** GitHub tokens are stored in localStorage without proper validation or sanitization, potentially allowing malicious tokens to be stored.

**Location:** `web-app/app/page.tsx:25`

---

### 9. [MEDIUM] [AI] Potential XSS Vulnerability in Markdown Generation

**Category:** Injection

**Description:** The generateReport function constructs markdown without proper sanitization of inputs, which could lead to XSS if the markdown is rendered in a browser.

**Location:** `web-app/app/page.tsx:60`

---

### 10. [MEDIUM] [AI] Potential Information Disclosure

**Category:** Information Disclosure

**Description:** The file `next-env.d.ts` may contain sensitive information, such as the location of the `.next/types/routes.d.ts` file. This information could potentially be used by an attacker to gain more insight into the application's structure and potentially identify vulnerabilities.

**Location:** `web-app/next-env.d.ts:3`

---

