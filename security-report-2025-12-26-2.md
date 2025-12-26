# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 8/100
**Date:** 2025-12-26

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 5 |
| Medium | 8 |
| Low | 1 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/api/scan/route.ts:682`

---

### 2. [MEDIUM] [AI] Missing Content Security Policy

**Category:** Security

**Description:** The code does not include a Content Security Policy (CSP) header, which can help prevent various types of web application vulnerabilities such as Cross-Site Scripting (XSS) attacks.

**Location:** `web-app/app/layout.tsx`

---

### 3. [HIGH] [AI] Hardcoded GitHub Personal Access Token

**Category:** Security

**Description:** The GitHub personal access token is stored in the browser's local storage, which could potentially be accessed by an attacker. This could lead to unauthorized access to the user's GitHub account.

**Location:** `web-app/app/page.tsx:45`

---

### 4. [MEDIUM] [AI] Lack of Input Validation

**Category:** Security

**Description:** The application does not perform proper input validation on the GitHub repository URL, which could lead to potential security vulnerabilities such as cross-site scripting (XSS) or other injection attacks.

**Location:** `web-app/app/page.tsx:101`

---

### 5. [HIGH] [AI] Github Token Exposed in Local Storage

**Category:** Sensitive Data Exposure

**Description:** Storing sensitive data such as GitHub Personal Access Tokens in local storage can lead to potential security risks as malicious scripts can access this data.

**Location:** `web-app/app/page.tsx:20`

---

### 6. [MEDIUM] [AI] Lack of Input Validation on GitHub URL

**Category:** Input Validation

**Description:** While there is a basic check for 'github.com', it may allow for malformed URLs that could lead to unwanted requests or errors.

**Location:** `web-app/app/page.tsx:70`

---

### 7. [HIGH] [AI] XSS Vulnerability in Markdown Generation

**Category:** Cross-Site Scripting

**Description:** User-supplied input (repoUrl, findings content) is inserted directly into the Markdown report without any sanitization, which could allow for XSS attacks if the content includes malicious scripts.

**Location:** `web-app/app/page.tsx:47`

---

### 8. [HIGH] [AI] Sensitive Information Storage in Local Storage

**Category:** Information Disclosure

**Description:** The GitHub token (Personal Access Token) is stored in the browser's local storage. This is generally discouraged for sensitive information because local storage is accessible to JavaScript code running within the same origin, increasing the risk of XSS attacks leading to token theft.

**Location:** `web-app/app/page.tsx:41`

---

### 9. [MEDIUM] [AI] Potential Cross-Site Scripting (XSS) via Markdown Report

**Category:** Cross-Site Scripting (XSS)

**Description:** The generated Markdown report could be vulnerable to XSS if the `finding.title`, `finding.description`, or `finding.file` contain malicious HTML or JavaScript code. When the markdown is rendered, this malicious code could be executed. Input sanitization/escaping should be implemented before including user-provided data into the markdown string.

**Location:** `web-app/app/page.tsx:63`

---

### 10. [HIGH] [AI] Sensitive Data Exposure via localStorage

**Category:** Data Protection

**Description:** GitHub tokens are stored in localStorage which is accessible via JavaScript and vulnerable to XSS attacks. Tokens should be stored in httpOnly cookies or more secure storage mechanisms.

**Location:** `web-app/app/page.tsx:22`

---

### 11. [MEDIUM] [AI] Insecure Direct Object Reference

**Category:** Access Control

**Description:** The API endpoint '/api/scan' is called directly without proper authentication or authorization checks on the client side.

**Location:** `web-app/app/page.tsx:70`

---

### 12. [MEDIUM] [AI] Incomplete Error Handling

**Category:** Error Handling

**Description:** Error handling in the fetch request is incomplete and may expose sensitive information in the error message.

**Location:** `web-app/app/page.tsx:77`

---

### 13. [MEDIUM] [AI] Unvalidated Redirect

**Category:** Injection

**Description:** The repoUrl is used directly in the API call without proper validation or sanitization, potentially leading to SSRF or other injection attacks.

**Location:** `web-app/app/page.tsx:70`

---

### 14. [MEDIUM] [AI] Insecure Token Transmission

**Category:** Data Protection

**Description:** GitHub tokens are sent in the request body without HTTPS enforcement, potentially exposing them in transit.

**Location:** `web-app/app/page.tsx:70`

---

