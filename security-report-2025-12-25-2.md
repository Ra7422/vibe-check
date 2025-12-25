# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 0/100
**Date:** 2025-12-25

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 28 |
| Medium | 60 |
| Low | 6 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/api/scan/route.ts:682`

---

### 2. [MEDIUM] [AI] Missing or incorrect semantic tags

**Category:** DOM structure

**Description:** The HTML contains elements that do not use the correct semantic tags, which can impact accessibility and SEO.

**Location:** `ai_flow_tester/src/analyzers.py`

---

### 3. [MEDIUM] [AI] Form accessibility issues

**Category:** Accessibility

**Description:** The HTML contains form elements that lack proper labels or ARIA attributes, making them difficult for users with disabilities to interact with.

**Location:** `ai_flow_tester/src/analyzers.py`

---

### 4. [MEDIUM] [AI] Missing alt text on images

**Category:** Accessibility

**Description:** Some images in the HTML do not have alternative text, which is important for users who are visually impaired.

**Location:** `ai_flow_tester/src/analyzers.py`

---

### 5. [LOW] [AI] Improper heading hierarchy

**Category:** DOM structure

**Description:** The heading tags (H1, H2, etc.) in the HTML are not used in a proper hierarchy, which can affect the structure and understandability of the content.

**Location:** `ai_flow_tester/src/analyzers.py`

---

### 6. [MEDIUM] [AI] Hidden elements that should be visible

**Category:** DOM structure

**Description:** The HTML contains elements that are hidden, but should be visible for a good user experience.

**Location:** `ai_flow_tester/src/analyzers.py`

---

### 7. [HIGH] [AI] Potential Exposure of Screenshot Data

**Category:** Data Handling

**Description:** The analyze method accepts a screenshot as bytes without any validation or sanitization, which could lead to sensitive user data being processed or logged inappropriately.

**Location:** `ai_flow_tester/src/analyzers.py:31`

---

### 8. [MEDIUM] [AI] Truncation of HTML Content

**Category:** Data Handling

**Description:** The _analyze_dom method truncates the HTML content if it exceeds 30,000 characters. This can lead to incomplete analyses if crucial content is omitted.

**Location:** `ai_flow_tester/src/analyzers.py:75`

---

### 9. [MEDIUM] [AI] Insecure Use of Async API Calls

**Category:** Concurrency

**Description:** The code does not handle potential exceptions from asynchronous calls to the LLM client, which could result in unhandled promise rejections or failures.

**Location:** `ai_flow_tester/src/analyzers.py:51`

---

### 10. [LOW] [AI] Hardcoded Prompt in Visual Analysis

**Category:** Configuration Management

**Description:** The prompts for visual and DOM analysis are hardcoded. This approach may not allow for easy updates or localization and could expose the system to pre-determined issues.

**Location:** `ai_flow_tester/src/analyzers.py:54`

---

### 11. [MEDIUM] [AI] Placeholder Response Handling

**Category:** Logic

**Description:** The _analyze_visual method returns a placeholder response which could confuse developers. It lacks proper error handling or indication of functionality being incomplete.

**Location:** `ai_flow_tester/src/analyzers.py:64`

---

### 12. [HIGH] [AI] Potential Information Disclosure in HTML Analysis

**Category:** Information Disclosure

**Description:** The code truncates HTML content to 30,000 characters before analysis, which could potentially expose sensitive information in the truncated portion if not properly sanitized.

**Location:** `ai_flow_tester/src/analyzers.py:80`

---

### 13. [MEDIUM] [AI] Unvalidated Input in LLM Prompts

**Category:** Injection

**Description:** The HTML content is directly inserted into LLM prompts without proper sanitization, which could lead to prompt injection vulnerabilities if the HTML contains malicious content.

**Location:** `ai_flow_tester/src/analyzers.py:80`

---

### 14. [LOW] [AI] Placeholder Vision Analysis

**Category:** Implementation

**Description:** The visual analysis is currently a placeholder and doesn't perform actual vision-based analysis, which could lead to incomplete security assessments.

**Location:** `ai_flow_tester/src/analyzers.py:50`

---

### 15. [MEDIUM] [AI] No Error Handling for LLM Responses

**Category:** Error Handling

**Description:** The code doesn't handle potential errors or malformed responses from the LLM client, which could lead to crashes or security issues.

**Location:** `ai_flow_tester/src/analyzers.py:60`

---

### 16. [MEDIUM] [AI] No Input Validation for Screenshot Data

**Category:** Input Validation

**Description:** The screenshot bytes are processed without validation, which could lead to issues if the input is malformed or malicious.

**Location:** `ai_flow_tester/src/analyzers.py:20`

---

### 17. [MEDIUM] [AI] No Rate Limiting for LLM Queries

**Category:** Denial of Service

**Description:** The code doesn't implement rate limiting for LLM queries, which could make it vulnerable to abuse or denial of service attacks.

**Location:** `ai_flow_tester/src/analyzers.py:60`

---

### 18. [HIGH] [AI] Unsanitized User Input

**Category:** Input Validation

**Description:** The code uses user input (`persona`) directly in the `analysis_prompt` without sanitizing it, which could lead to potential code injection vulnerabilities.

**Location:** `ai_flow_tester/src/generators.py:87`

---

### 19. [MEDIUM] [AI] Hardcoded Sensitive Data

**Category:** Data Exposure

**Description:** The code contains hardcoded sensitive data (e.g., API keys, credentials) in the `PERSONAS` dictionary, which could be a security risk if the code is exposed.

**Location:** `ai_flow_tester/src/generators.py:31`

---

### 20. [HIGH] [AI] Insecure URL Handling

**Category:** Input Validation

**Description:** The `url` parameter in the `generate_journey` method is not validated or sanitized, potentially allowing for injection attacks or manipulation of input parameters.

**Location:** `ai_flow_tester/src/generators.py:56`

---

### 21. [MEDIUM] [AI] Excessive Data Exposure

**Category:** Information Disclosure

**Description:** The `Visible Text Preview` output in the `analysis_prompt` may expose sensitive information if the page context contains confidential data.

**Location:** `ai_flow_tester/src/generators.py:48`

---

### 22. [HIGH] [AI] Potential Injection in Analysis Prompt

**Category:** Injection Flaws

**Description:** The inclusion of user-provided data (e.g., `url` and `page_context`) in the `analysis_prompt` string without escaping may allow for injection attacks against the LLM service.

**Location:** `ai_flow_tester/src/generators.py:43`

---

### 23. [MEDIUM] [AI] Unrestricted Persona Usage

**Category:** Access Control

**Description:** The method allows any persona from the `PERSONAS` dictionary to be specified without checking against a whitelist, potentially allowing misuse of adversarial personas.

**Location:** `ai_flow_tester/src/generators.py:57`

---

### 24. [MEDIUM] [AI] Lack of Exception Handling

**Category:** Error Handling

**Description:** The `generate_journey` function does not implement exception handling for the LLM query, which could lead to unhandled errors and information leakage.

**Location:** `ai_flow_tester/src/generators.py:61`

---

### 25. [HIGH] [AI] Hardcoded Credentials in LLM Prompts

**Category:** Information Disclosure

**Description:** The code constructs LLM prompts with potentially sensitive information (URL, page context) that could be exposed if the LLM responses are logged or stored improperly.

**Location:** `ai_flow_tester/src/generators.py:100`

---

### 26. [MEDIUM] [AI] Unvalidated User Input in LLM Prompts

**Category:** Injection

**Description:** The page_context and URL parameters are directly interpolated into LLM prompts without sanitization, which could lead to prompt injection if malicious content is provided.

**Location:** `ai_flow_tester/src/generators.py:100`

---

### 27. [MEDIUM] [AI] Potential Information Exposure in Error States

**Category:** Information Disclosure

**Description:** The code doesn't show handling of LLM errors or failures, which could expose sensitive information if errors occur during prompt processing.

**Location:** `ai_flow_tester/src/generators.py:100`

---

### 28. [MEDIUM] [AI] Insecure Default Configuration

**Category:** Configuration

**Description:** The code uses a default persona ('default') if an invalid persona is provided, which might not be appropriate for all security contexts.

**Location:** `ai_flow_tester/src/generators.py:90`

---

### 29. [MEDIUM] [AI] Potential Denial of Service via max_steps Parameter

**Category:** Denial of Service

**Description:** The max_steps parameter isn't validated or limited, which could allow resource exhaustion if an excessively large value is provided.

**Location:** `ai_flow_tester/src/generators.py:85`

---

### 30. [HIGH] [AI] Unsanitized User Input

**Category:** Input Validation

**Description:** The code does not perform input validation on the `url` and `persona` parameters, which could lead to potential security vulnerabilities such as Cross-Site Scripting (XSS) or URL manipulation attacks.

**Location:** `ai_flow_tester/src/runner.py:140`

---

### 31. [MEDIUM] [AI] Hardcoded Credentials

**Category:** Sensitive Data Exposure

**Description:** The code uses hardcoded credentials for the `LLMProvider` in the configuration, which could expose sensitive information if the code is shared or deployed in an insecure environment.

**Location:** `ai_flow_tester/src/runner.py:86`

---

### 32. [HIGH] [AI] Insecure Configuration Loading

**Category:** Configuration Management

**Description:** The application loads configuration files without validation and defaults. If an attacker can influence the file path or contents of '.safeguard.yaml', they could potentially inject harmful configurations.

**Location:** `ai_flow_tester/src/runner.py:50`

---

### 33. [HIGH] [AI] Potential Denial of Service via URL Input

**Category:** Input Validation

**Description:** The `run` method accepts a URL as input without validation. An attacker could exploit this to perform a denial of service attack with a malformed or malicious URL.

**Location:** `ai_flow_tester/src/runner.py:86`

---

### 34. [MEDIUM] [AI] Use of Async without Exception Handling

**Category:** Error Handling

**Description:** The asynchronous code does not handle exceptions, which could lead to unhandled promise rejections and application crashes if an error occurs during the execution of Playwright or network requests.

**Location:** `ai_flow_tester/src/runner.py:95`

---

### 35. [LOW] [AI] Hardcoded Video Directory

**Category:** Hardcoding

**Description:** The directory for recording videos is hardcoded to './test-videos'. This could lead to unexpected overwriting of data and potential data exfiltration if not properly managed.

**Location:** `ai_flow_tester/src/runner.py:72`

---

### 36. [MEDIUM] [AI] Hardcoded Default Configuration

**Category:** Configuration Management

**Description:** The code has hardcoded default configuration values which could lead to security misconfigurations if the configuration file is missing or malformed.

**Location:** `ai_flow_tester/src/runner.py:60`

---

### 37. [HIGH] [AI] Potential Path Traversal in Config Loading

**Category:** File Handling

**Description:** The code loads configuration files without proper path validation, which could allow path traversal attacks if an attacker can control the config_path parameter.

**Location:** `ai_flow_tester/src/runner.py:52`

---

### 38. [HIGH] [AI] Unvalidated User Input in URL Parameter

**Category:** Input Validation

**Description:** The URL parameter passed to the run method is not validated or sanitized before being used, which could lead to SSRF or other injection attacks.

**Location:** `ai_flow_tester/src/runner.py:87`

---

### 39. [MEDIUM] [AI] Insecure Default Browser Settings

**Category:** Browser Security

**Description:** The default browser configuration includes video recording and screenshot on failure, which could expose sensitive information if not properly secured.

**Location:** `ai_flow_tester/src/runner.py:68`

---

### 40. [MEDIUM] [AI] No Rate Limiting for LLM API Calls

**Category:** API Security

**Description:** The MultiLLMClient is used without any rate limiting or throttling, which could lead to excessive API calls and potential abuse.

**Location:** `ai_flow_tester/src/runner.py:40`

---

### 41. [MEDIUM] [AI] No Error Handling for LLM API Failures

**Category:** Error Handling

**Description:** There is no proper error handling for LLM API failures, which could lead to unexpected behavior or crashes.

**Location:** `ai_flow_tester/src/runner.py:40`

---

### 42. [MEDIUM] [AI] Insecure Default Video Storage

**Category:** Data Storage

**Description:** Test videos are stored in a default directory (./test-videos) without proper access controls or encryption.

**Location:** `ai_flow_tester/src/runner.py:102`

---

### 43. [HIGH] [AI] Use of hardcoded API key

**Category:** API Security

**Description:** The code uses a hardcoded API key, which can be a security vulnerability if the key is exposed. This can lead to unauthorized access to the API and potential data breaches.

**Location:** `ai_flow_tester/src/selectors.py:27`

---

### 44. [MEDIUM] [AI] Lack of input validation

**Category:** Input Validation

**Description:** The code does not perform any input validation on the `description` parameter passed to the `find_by_description` function. This can lead to potential injection attacks, such as SQL injection or cross-site scripting (XSS).

**Location:** `ai_flow_tester/src/selectors.py:59`

---

### 45. [MEDIUM] [AI] Potential information disclosure

**Category:** Information Disclosure

**Description:** The code includes a preview of the HTML content, which may contain sensitive information. This can lead to potential information disclosure if the application is not properly secured.

**Location:** `ai_flow_tester/src/selectors.py:88`

---

### 46. [HIGH] [AI] Potentially leaking HTML content

**Category:** Information Disclosure

**Description:** The method `find_by_description` retrieves the entire HTML content of the page and sends it to an LLM, which may expose sensitive information if the page contains private data.

**Location:** `ai_flow_tester/src/selectors.py:48`

---

### 47. [MEDIUM] [AI] Improper error handling

**Category:** Error Handling

**Description:** Exceptions in the selector validation and fallback handling are silently ignored. This could lead to unhandled errors and make debugging difficult.

**Location:** `ai_flow_tester/src/selectors.py:29`

---

### 48. [HIGH] [AI] Lack of Input Sanitization

**Category:** Injection Attack

**Description:** User-supplied descriptions in `find_by_description` are not sanitized. This could lead to injection attacks or unintended behavior when interacting with the LLM.

**Location:** `ai_flow_tester/src/selectors.py:47`

---

### 49. [MEDIUM] [AI] No rate limiting on LLM queries

**Category:** Denial of Service

**Description:** The system does not implement any rate limiting for queries to the LLM, which could lead to abuse or denial of service if misused.

**Location:** `ai_flow_tester/src/selectors.py:50`

---

### 50. [LOW] [AI] Unrestricted access to selector cache

**Category:** Logic Flaw

**Description:** The `selector_cache` could be manipulated if the description is crafted maliciously, leading to incorrect behavior in selector retrieval.

**Location:** `ai_flow_tester/src/selectors.py:23`

---

### 51. [HIGH] [AI] Potential HTML Injection via AI-Generated Selectors

**Category:** Injection

**Description:** The code uses AI-generated selectors directly from HTML content without proper sanitization, which could lead to HTML injection if the AI response is maliciously crafted.

**Location:** `ai_flow_tester/src/selectors.py:50`

---

### 52. [MEDIUM] [AI] Insufficient Error Handling in Selector Validation

**Category:** Error Handling

**Description:** The code uses bare except clauses when validating selectors, which could mask important exceptions and make debugging difficult.

**Location:** `ai_flow_tester/src/selectors.py:55`

---

### 53. [MEDIUM] [AI] Potential Information Exposure via HTML Preview

**Category:** Information Exposure

**Description:** The code sends large portions of HTML (20,000 and 25,000 characters) to the AI service, which might contain sensitive information that shouldn't be exposed to external services.

**Location:** `ai_flow_tester/src/selectors.py:45`

---

### 54. [MEDIUM] [AI] No Input Validation for Description Parameter

**Category:** Input Validation

**Description:** The description parameter passed to find_by_description is not validated, which could lead to unexpected behavior or injection if malformed input is provided.

**Location:** `ai_flow_tester/src/selectors.py:28`

---

### 55. [MEDIUM] [AI] No Rate Limiting for AI Queries

**Category:** Rate Limiting

**Description:** The code doesn't implement any rate limiting for AI queries, which could lead to excessive API calls and potential denial of service if abused.

**Location:** `ai_flow_tester/src/selectors.py:50`

---

### 56. [MEDIUM] [AI] Potential Memory Issues with Large HTML Content

**Category:** Resource Management

**Description:** The code loads and processes large portions of HTML content (up to 25,000 characters) which could cause memory issues if the HTML is very large.

**Location:** `ai_flow_tester/src/selectors.py:45`

---

### 57. [MEDIUM] [AI] No Timeout for AI Queries

**Category:** Timeout

**Description:** The code doesn't specify any timeout for AI queries, which could lead to hanging if the AI service is slow or unresponsive.

**Location:** `ai_flow_tester/src/selectors.py:50`

---

### 58. [CRITICAL] [AI] Insecure Hardcoded Credentials

**Category:** Credentials Management

**Description:** The script contains hardcoded credentials, which can be a security risk if the code is exposed or accessed by unauthorized users.

**Location:** `run_flow_tests.py:15`

---

### 59. [MEDIUM] [AI] Potential Denial of Service (DoS) Attack

**Category:** Denial of Service

**Description:** The script launches a new browser instance for each flow test, which can lead to resource exhaustion and potential Denial of Service (DoS) attacks if the script is run repeatedly or on a large scale.

**Location:** `run_flow_tests.py:54`

---

### 60. [MEDIUM] [AI] Lack of Input Validation

**Category:** Input Validation

**Description:** The script does not perform any input validation on the `base_url` parameter, which could lead to injection attacks if the input is not properly sanitized.

**Location:** `run_flow_tests.py:41`

---

### 61. [MEDIUM] [AI] Insecure File Path Handling

**Category:** File Handling

**Description:** The script creates a directory for storing screenshots without properly validating or sanitizing the path, which could lead to directory traversal attacks.

**Location:** `run_flow_tests.py:43`

---

### 62. [HIGH] [AI] Missing Input Validation for Base URL

**Category:** Input Validation

**Description:** The base_url parameter used in Meedi8FlowTester is not validated, potentially allowing incorrect or malicious URLs to be passed.

**Location:** `run_flow_tests.py:35`

---

### 63. [HIGH] [AI] Uncontrolled Installation of Dependencies

**Category:** Dependency Management

**Description:** The code automatically installs the 'playwright' package and its dependencies without user consent or version control, which could lead to arbitrary code execution.

**Location:** `run_flow_tests.py:13`

---

### 64. [MEDIUM] [AI] Hardcoded User-Agent String

**Category:** Information Leakage

**Description:** The user agent string is hardcoded, which could reveal information about the testing environment. It can be a potential vector for fingerprinting.

**Location:** `run_flow_tests.py:67`

---

### 65. [MEDIUM] [AI] Hardcoded Credentials in User Agent

**Category:** Information Disclosure

**Description:** The user agent string contains hardcoded system information (Macintosh; Intel Mac OS X 10_15_7) which could reveal unnecessary details about the testing environment.

**Location:** `run_flow_tests.py:38`

---

### 66. [MEDIUM] [AI] No Error Handling for Playwright Installation

**Category:** Error Handling

**Description:** The code attempts to install Playwright if not found but doesn't handle potential installation failures gracefully.

**Location:** `run_flow_tests.py:12`

---

### 67. [MEDIUM] [AI] No Rate Limiting or Throttling

**Category:** Denial of Service

**Description:** The script doesn't implement any rate limiting or request throttling which could lead to excessive requests to the production site.

**Location:** `run_flow_tests.py`

---

### 68. [HIGH] [AI] No Authentication for Production Testing

**Category:** Authentication

**Description:** The script tests production flows without any authentication mechanism, which could expose sensitive flows to unauthorized access.

**Location:** `run_flow_tests.py`

---

### 69. [MEDIUM] [AI] No Input Validation for Base URL

**Category:** Input Validation

**Description:** The base URL is not validated before use, which could lead to SSRF or other injection attacks if manipulated.

**Location:** `run_flow_tests.py:28`

---

### 70. [HIGH] [AI] Sensitive Information in Screenshots

**Category:** Information Disclosure

**Description:** Screenshots are saved to a local directory without any sanitization, which could capture sensitive information from the production site.

**Location:** `run_flow_tests.py:30`

---

### 71. [MEDIUM] [AI] No Timeout for Playwright Operations

**Category:** Error Handling

**Description:** Playwright operations don't have explicit timeouts, which could lead to hanging processes.

**Location:** `run_flow_tests.py`

---

### 72. [HIGH] [AI] SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection - user input may be concatenated into queries

**Location:** `run_scan.py`

---

### 73. [HIGH] [AI] Dynamic Code Execution

**Category:** Code Execution

**Description:** Dynamic code execution can run arbitrary code and is a security risk

**Location:** `run_scan.py`

---

### 74. [MEDIUM] [AI] Dangerous innerHTML

**Category:** XSS

**Description:** Direct innerHTML can lead to Cross-Site Scripting attacks

**Location:** `run_scan.py`

---

### 75. [MEDIUM] [AI] Insecure Protocol

**Category:** Configuration

**Description:** Using insecure protocol exposes data to interception

**Location:** `run_scan.py`

---

### 76. [HIGH] [AI] Disabled SSL/Security

**Category:** Configuration

**Description:** Security verification is disabled

**Location:** `run_scan.py`

---

### 77. [MEDIUM] [AI] Debug Mode Enabled

**Category:** Configuration

**Description:** Debug mode may expose sensitive information

**Location:** `run_scan.py`

---

### 78. [MEDIUM] [AI] Console Log in Production Code

**Category:** Data Exposure

**Description:** Console log may expose sensitive data

**Location:** `run_scan.py`

---

### 79. [HIGH] [AI] Hardcoded Secrets Detection

**Category:** Sensitive Data Exposure

**Description:** Potential exposure of hardcoded API keys, secrets, and passwords due to patterns designed to detect them.

**Location:** `run_scan.py`

---

### 80. [HIGH] [AI] Potential SQL Injection Risk

**Category:** Injection

**Description:** Potential SQL injection - user input may be concatenated into queries.

**Location:** `run_scan.py`

---

### 81. [HIGH] [AI] Dynamic Code Execution Risk

**Category:** Code Execution

**Description:** Dynamic code execution can run arbitrary code and is a security risk.

**Location:** `run_scan.py`

---

### 82. [MEDIUM] [AI] Direct innerHTML Usage

**Category:** XSS

**Description:** Direct innerHTML assignment can lead to Cross-Site Scripting attacks.

**Location:** `run_scan.py`

---

### 83. [MEDIUM] [AI] Insecure Protocol Usage

**Category:** Configuration

**Description:** Using insecure protocol exposes data to interception.

**Location:** `run_scan.py`

---

### 84. [HIGH] [AI] Disabled SSL/Security Verification

**Category:** Configuration

**Description:** Security verification is disabled, exposing connections to attacks.

**Location:** `run_scan.py`

---

### 85. [MEDIUM] [AI] Debug Mode Enabled

**Category:** Configuration

**Description:** Debug mode may expose sensitive information.

**Location:** `run_scan.py`

---

### 86. [MEDIUM] [AI] Console Log in Production Code

**Category:** Data Exposure

**Description:** Console log may expose sensitive data in production environment.

**Location:** `run_scan.py`

---

### 87. [CRITICAL] [AI] Hardcoded Credentials Detection

**Category:** Secrets Management

**Description:** The script contains patterns to detect hardcoded credentials which could lead to unauthorized access if exposed

**Location:** `run_scan.py:20`

---

### 88. [HIGH] [AI] Dynamic Code Execution Detection

**Category:** Code Execution

**Description:** The script detects dynamic code execution patterns which can be exploited for remote code execution attacks

**Location:** `run_scan.py:50`

---

### 89. [HIGH] [AI] SQL Injection Detection

**Category:** Injection

**Description:** The script detects SQL injection patterns which could allow attackers to manipulate database queries

**Location:** `run_scan.py:42`

---

### 90. [MEDIUM] [AI] Insecure Protocol Detection

**Category:** Configuration

**Description:** The script detects insecure protocol usage which could expose data to interception

**Location:** `run_scan.py:54`

---

### 91. [MEDIUM] [AI] Debug Mode Detection

**Category:** Configuration

**Description:** The script detects debug mode patterns which could expose sensitive information

**Location:** `run_scan.py:62`

---

### 92. [MEDIUM] [AI] Console Log Detection

**Category:** Data Exposure

**Description:** The script detects console log patterns that may expose sensitive data

**Location:** `run_scan.py:66`

---

### 93. [MEDIUM] [AI] Insecure File Handling

**Category:** File Handling

**Description:** The script does not explicitly handle file permissions or encryption when reading/writing files

**Location:** `run_scan.py:1`

---

### 94. [MEDIUM] [AI] Potential Path Traversal

**Category:** Path Traversal

**Description:** The script uses pathlib.Path without explicit validation of user-supplied paths

**Location:** `run_scan.py:1`

---

### 95. [MEDIUM] [AI] Insecure Error Handling

**Category:** Error Handling

**Description:** The script does not explicitly handle exceptions which could lead to information leakage

**Location:** `run_scan.py:1`

---

### 96. [MEDIUM] [AI] Lack of Input Validation

**Category:** Input Validation

**Description:** The code does not perform any input validation, which could lead to security vulnerabilities if the SecurityScanner class is used with untrusted input.

**Location:** `security_scanner/__init__.py`

---

