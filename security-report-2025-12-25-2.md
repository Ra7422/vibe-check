# Security Scan Report

**Repository:** https://github.com/Ra7422/vibe-check
**Score:** 0/100
**Date:** 2025-12-25

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 25 |
| Medium | 48 |
| Low | 7 |

## Issues to Fix

Please review and fix the following security issues:

### 1. [LOW] Console Logging

**Category:** Best Practice

**Description:** Console statements may leak sensitive information in production.

**Location:** `web-app/app/api/scan/route.ts:682`

---

### 2. [HIGH] [AI] Untrusted Data Input

**Category:** Input Validation

**Description:** The code uses user-supplied data (persona) without properly validating or sanitizing it. This could lead to potential security issues such as injection attacks.

**Location:** `ai_flow_tester/src/generators.py:49`

---

### 3. [CRITICAL] [AI] Hardcoded Credentials

**Category:** Sensitive Information Exposure

**Description:** The code contains hardcoded credentials (API keys, tokens, etc.) that could be exposed and used by attackers.

**Location:** `ai_flow_tester/src/generators.py:82`

---

### 4. [HIGH] [AI] Exposure of Internal Logic

**Category:** Information Exposure

**Description:** The 'generate_journey' function exposes internal logic through generated prompts that include potential sensitive data like page_context details. This could lead to accidental information leakage or intelligent attacks if insights are gained from the generated prompts.

**Location:** `ai_flow_tester/src/generators.py:76`

---

### 5. [HIGH] [AI] Lack of Input Validation

**Category:** Input Validation

**Description:** The inputs to the 'generate_journey' method (like 'url', 'page_context') are not validated. This can lead to security issues such as injection attacks or processing malicious data if not properly handled.

**Location:** `ai_flow_tester/src/generators.py:63`

---

### 6. [MEDIUM] [AI] Potential for Insecure Usage of External LLM Outputs

**Category:** External Dependency Security

**Description:** The outputs of the LLM query are not validated or sanitized before being used, which may lead to unsafe operations or further security issues downstream.

**Location:** `ai_flow_tester/src/generators.py:84`

---

### 7. [HIGH] [AI] Hardcoded Credentials or Sensitive Information

**Category:** Sensitive Data Exposure

**Description:** The code contains a hardcoded URL and page context which might expose sensitive information if not properly sanitized.

**Location:** `ai_flow_tester/src/generators.py:70`

---

### 8. [MEDIUM] [AI] Insecure Direct Object Reference

**Category:** Access Control

**Description:** The `persona` parameter is directly used without validation, which could allow unauthorized access to different user personas.

**Location:** `ai_flow_tester/src/generators.py:50`

---

### 9. [HIGH] [AI] Potential Injection Vulnerability

**Category:** Injection

**Description:** The `url` parameter is directly interpolated into the prompt without sanitization, which could lead to prompt injection attacks.

**Location:** `ai_flow_tester/src/generators.py:70`

---

### 10. [MEDIUM] [AI] Insufficient Input Validation

**Category:** Input Validation

**Description:** The `page_context` parameter is used without validation, which could lead to unexpected behavior or security issues.

**Location:** `ai_flow_tester/src/generators.py:48`

---

### 11. [MEDIUM] [AI] Excessive Data Exposure

**Category:** Data Exposure

**Description:** The visible text preview is truncated to 2000 characters, but this might still expose sensitive information if not properly handled.

**Location:** `ai_flow_tester/src/generators.py:72`

---

### 12. [MEDIUM] [AI] Potential Denial of Service

**Category:** Denial of Service

**Description:** The `max_steps` parameter is not validated, which could allow an attacker to generate an excessively large number of steps, leading to resource exhaustion.

**Location:** `ai_flow_tester/src/generators.py:52`

---

### 13. [HIGH] [AI] Potential Cross-Site Scripting (XSS) Vulnerability

**Category:** Security

**Description:** The code appears to be using user-provided input (e.g., `TestStep.selector`, `TestStep.value`, `TestStep.expected`) directly in the Playwright actions without any input validation or sanitization. This could potentially lead to a Cross-Site Scripting (XSS) vulnerability if the user-provided input contains malicious scripts.

**Location:** `ai_flow_tester/src/runner.py:14`

---

### 14. [MEDIUM] [AI] Lack of Input Validation

**Category:** Security

**Description:** The code does not perform any input validation on the user-provided values in the `TestStep` dataclass. This could lead to other types of vulnerabilities, such as SQL injection or command injection, if these values are used in unsafe ways later in the code.

**Location:** `ai_flow_tester/src/runner.py:14`

---

### 15. [MEDIUM] [AI] Potential Sensitive Data Exposure

**Category:** Security

**Description:** The code appears to be saving screenshots in the `./test-videos` directory, which may contain sensitive information. It is important to ensure that these screenshots do not contain any sensitive data and that access to the directory is properly restricted.

**Location:** `ai_flow_tester/src/runner.py:89`

---

### 16. [HIGH] [AI] Improper Input Validation

**Category:** Input Validation

**Description:** The 'url' parameter in the run method is used directly in the page.goto() call without validation, potentially allowing for open redirect or SSRF vulnerabilities.

**Location:** `ai_flow_tester/src/runner.py:87`

---

### 17. [MEDIUM] [AI] Sensitive Data Exposure

**Category:** Data Protection

**Description:** Configuration data loaded from files is not handled securely; sensitive information could be exposed if the configuration includes such data.

**Location:** `ai_flow_tester/src/runner.py:55`

---

### 18. [HIGH] [AI] Potential Insecure Deserialization

**Category:** Deserialization

**Description:** The use of yaml.safe_load without proper validation opens up the potential for YAML deserialization vulnerabilities, especially if malicious content is introduced into the configuration file.

**Location:** `ai_flow_tester/src/runner.py:56`

---

### 19. [MEDIUM] [AI] Hardcoded Default Configuration

**Category:** Configuration Management

**Description:** The code has hardcoded default configuration values which could lead to security issues if not properly overridden. The default configuration includes sensitive settings like LLM providers and browser behavior.

**Location:** `ai_flow_tester/src/runner.py:65`

---

### 20. [HIGH] [AI] Insecure File Handling

**Category:** File Handling

**Description:** The code reads YAML configuration files without proper validation or sanitization, which could lead to arbitrary code execution if malicious YAML content is provided.

**Location:** `ai_flow_tester/src/runner.py:52`

---

### 21. [HIGH] [AI] No Input Validation for URL

**Category:** Input Validation

**Description:** The URL parameter passed to the run method is not validated or sanitized, which could lead to SSRF (Server-Side Request Forgery) or other injection attacks.

**Location:** `ai_flow_tester/src/runner.py:85`

---

### 22. [CRITICAL] [AI] No Authentication for LLM Providers

**Category:** Authentication

**Description:** The MultiLLMClient is initialized without any authentication or API key management, which could expose sensitive LLM provider credentials or allow unauthorized access.

**Location:** `ai_flow_tester/src/runner.py:45`

---

### 23. [MEDIUM] [AI] No Rate Limiting for LLM Calls

**Category:** Rate Limiting

**Description:** The code does not implement any rate limiting for LLM API calls, which could lead to excessive usage and potential denial of service.

**Location:** `ai_flow_tester/src/runner.py:45`

---

### 24. [MEDIUM] [AI] No Error Handling for Browser Operations

**Category:** Error Handling

**Description:** The code does not properly handle errors that might occur during browser operations, which could lead to unexpected behavior or crashes.

**Location:** `ai_flow_tester/src/runner.py:90`

---

### 25. [MEDIUM] [AI] No Timeout for LLM Operations

**Category:** Timeout Management

**Description:** The code does not set timeouts for LLM operations, which could lead to hanging or unresponsive behavior.

**Location:** `ai_flow_tester/src/runner.py:45`

---

### 26. [MEDIUM] [AI] No Secure Default for Headless Mode

**Category:** Configuration Management

**Description:** The default configuration for headless mode is set to True, which might not be secure for all environments.

**Location:** `ai_flow_tester/src/runner.py:65`

---

### 27. [HIGH] [AI] Potential Injection Vulnerability

**Category:** Code Injection

**Description:** The code uses user-provided input (the `description` parameter) to generate a prompt for the language model without proper sanitization or validation. This could potentially lead to code injection vulnerabilities if the input contains malicious code.

**Location:** `ai_flow_tester/src/selectors.py:55`

---

### 28. [HIGH] [AI] Improper exception handling in locator checks

**Category:** Error handling

**Description:** The code catches all exceptions without handling specific exceptions appropriately, making it difficult to identify the root cause of errors when locators fail. This could lead to silent failures.

**Location:** `ai_flow_tester/src/selectors.py:36`

---

### 29. [HIGH] [AI] Potential for injection in AI prompt

**Category:** Input Validation

**Description:** The description from an untrusted source is directly injected into the AI prompt without sanitization, creating a risk of prompt injection attacks.

**Location:** `ai_flow_tester/src/selectors.py:52`

---

### 30. [MEDIUM] [AI] Selector cache does not expire or limit size

**Category:** Resource Management

**Description:** The selector cache does not implement any size limit or expiration mechanism, which could lead to excessive memory usage over time.

**Location:** `ai_flow_tester/src/selectors.py:28`

---

### 31. [LOW] [AI] Use of deprecated string type hinting

**Category:** Code Quality

**Description:** The use of 'list[str]' in type hints might cause compatibility issues in older Python versions (prior to 3.9). Use 'List[str]' from 'typing' for broader compatibility.

**Location:** `ai_flow_tester/src/selectors.py:12`

---

### 32. [MEDIUM] [AI] Hardcoded prompt structure

**Category:** Maintenance

**Description:** The AI prompt used for querying the model is hardcoded, making it difficult to modify or adjust its structure or the parameters it uses without altering the source code.

**Location:** `ai_flow_tester/src/selectors.py:52`

---

### 33. [HIGH] [AI] Potential HTML Injection via AI-Generated Selectors

**Category:** Injection

**Description:** The code uses AI-generated selectors directly from HTML content without proper sanitization, which could lead to HTML injection if the AI response is maliciously crafted.

**Location:** `ai_flow_tester/src/selectors.py:50`

---

### 34. [MEDIUM] [AI] Insecure Error Handling

**Category:** Error Handling

**Description:** The code uses bare except clauses which can hide important exceptions and make debugging difficult. This could lead to security issues being overlooked.

**Location:** `ai_flow_tester/src/selectors.py:55`

---

### 35. [MEDIUM] [AI] Potential Information Disclosure

**Category:** Information Disclosure

**Description:** The code sends large HTML previews (20,000 and 25,000 characters) to an external LLM service, which could contain sensitive information if not properly sanitized.

**Location:** `ai_flow_tester/src/selectors.py:45`

---

### 36. [MEDIUM] [AI] Unvalidated External Input

**Category:** Input Validation

**Description:** The description parameter in find_by_description is used directly in selector generation without validation, which could lead to injection or other issues.

**Location:** `ai_flow_tester/src/selectors.py:28`

---

### 37. [MEDIUM] [AI] Potential Denial of Service

**Category:** Denial of Service

**Description:** The code doesn't limit the size of the HTML content sent to the LLM service, which could lead to performance issues or denial of service if very large pages are processed.

**Location:** `ai_flow_tester/src/selectors.py:45`

---

### 38. [LOW] [AI] Insecure Direct Object Reference

**Category:** Access Control

**Description:** The selector cache uses the description as a key without proper access control, which could potentially allow unauthorized access to cached selectors.

**Location:** `ai_flow_tester/src/selectors.py:18`

---

### 39. [HIGH] [AI] Hardcoded Credentials

**Category:** Sensitive Data Exposure

**Description:** The code contains hardcoded credentials, which can be a security risk if the code is ever exposed.

**Location:** `run_flow_tests.py:78`

---

### 40. [MEDIUM] [AI] Lack of Error Handling

**Category:** Error Handling

**Description:** The code does not handle exceptions properly, which can lead to unexpected behavior and potential security issues.

**Location:** `run_flow_tests.py:67`

---

### 41. [MEDIUM] [AI] Insecure Playwright Configuration

**Category:** Configuration

**Description:** The Playwright configuration does not set the 'ignoreHTTPSErrors' option to 'true', which can lead to issues with HTTPS connections.

**Location:** `run_flow_tests.py:54`

---

### 42. [HIGH] [AI] Insecure Dynamic URL Construction

**Category:** URL Manipulation

**Description:** The base_url can be potentially manipulated if not properly validated, leading to possible phishing or data exfiltration.

**Location:** `run_flow_tests.py:42`

---

### 43. [MEDIUM] [AI] Uncaught Exceptions During Install

**Category:** Error Handling

**Description:** If the subprocess command fails during the playwright installation, the script will not handle the exception, potentially causing the program to crash.

**Location:** `run_flow_tests.py:18`

---

### 44. [MEDIUM] [AI] Improper Handling of Installed Packages

**Category:** Dependency Management

**Description:** The script installs packages without verifying if they are already installed or logging the installation. This can lead to failures if the installation process hangs.

**Location:** `run_flow_tests.py:17`

---

### 45. [LOW] [AI] Using Hardcoded User-Agent

**Category:** Information Disclosure

**Description:** Hardcoding a User-Agent string may expose the application to unforeseen issues, as server behavior could change based on the User-Agent.

**Location:** `run_flow_tests.py:55`

---

### 46. [LOW] [AI] Lack of Input Validation on Test Cases

**Category:** Input Validation

**Description:** There is no validation of the flow names or logic that could lead to unexpected behavior or side effects during the testing process.

**Location:** `run_flow_tests.py:56`

---

### 47. [MEDIUM] [AI] Hardcoded Credentials in User Agent

**Category:** Information Exposure

**Description:** The user agent string contains hardcoded system information (Macintosh; Intel Mac OS X 10_15_7) which could expose unnecessary details about the testing environment.

**Location:** `run_flow_tests.py:42`

---

### 48. [MEDIUM] [AI] No Error Handling for Playwright Installation

**Category:** Error Handling

**Description:** The code attempts to install Playwright if not found but doesn't handle potential installation failures or permission issues.

**Location:** `run_flow_tests.py:12`

---

### 49. [MEDIUM] [AI] No Rate Limiting or Throttling

**Category:** Performance

**Description:** The script doesn't implement any rate limiting or request throttling which could lead to performance issues or being blocked by the server.

**Location:** `run_flow_tests.py`

---

### 50. [MEDIUM] [AI] No Input Validation for Base URL

**Category:** Input Validation

**Description:** The base_url parameter isn't validated for proper URL format or scheme (http/https).

**Location:** `run_flow_tests.py:36`

---

### 51. [LOW] [AI] No Cleanup of Screenshots Directory

**Category:** Resource Management

**Description:** The script creates a screenshots directory but doesn't clean up old screenshots between runs.

**Location:** `run_flow_tests.py:37`

---

### 52. [MEDIUM] [AI] No Timeout for Playwright Operations

**Category:** Error Handling

**Description:** The script doesn't set timeouts for Playwright operations which could lead to hanging if the site is unresponsive.

**Location:** `run_flow_tests.py`

---

### 53. [HIGH] [AI] No Authentication for Production Testing

**Category:** Authentication

**Description:** The script tests production flows without any authentication mechanism which could lead to unauthorized access if not properly controlled.

**Location:** `run_flow_tests.py`

---

### 54. [HIGH] [AI] Hardcoded Credentials

**Category:** Security

**Description:** The code contains hardcoded credentials, which can be a security vulnerability if the credentials are sensitive or used in production.

**Location:** `shared/src/cli.py:27`

---

### 55. [MEDIUM] [AI] Insecure Logging

**Category:** Security

**Description:** The code logs sensitive information, such as the URL and persona, which could potentially expose sensitive data.

**Location:** `shared/src/cli.py:45`

---

### 56. [MEDIUM] [AI] Lack of Error Handling

**Category:** Reliability

**Description:** The code does not have proper error handling, which could lead to unexpected behavior or crashes in the event of an error.

**Location:** `shared/src/cli.py:74`

---

### 57. [MEDIUM] [AI] Unsafe File Handling

**Category:** Security

**Description:** The code allows for arbitrary file paths to be specified as input, which could lead to directory traversal attacks or other file-related vulnerabilities.

**Location:** `shared/src/cli.py:91`

---

### 58. [MEDIUM] [AI] Potential HTTP URL Handling

**Category:** Information Disclosure

**Description:** The code processes URLs without validation or sanitization, which may lead to issues if an attacker provides a malicious URL or if the URL points to a sensitive resource.

**Location:** `shared/src/cli.py:14`

---

### 59. [HIGH] [AI] Path Traversal via Output Path

**Category:** File Access

**Description:** The output path is taken from user input without validation, which could allow for path traversal attacks. An attacker may specify a path outside of the intended output directory.

**Location:** `shared/src/cli.py:38`

---

### 60. [HIGH] [AI] Execution of Async Function Without Error Handling

**Category:** Error Handling

**Description:** The async function 'run()' is called without any try/except handling, which could lead to unhandled exceptions crashing the application.

**Location:** `shared/src/cli.py:28`

---

### 61. [HIGH] [AI] Command Injection via Checks and Compliance Options

**Category:** Command Injection

**Description:** The checks and compliance parameters are not validated or sanitized, potentially leading to command injection vulnerabilities if the parameters are used in shell commands.

**Location:** `shared/src/cli.py:68`

---

### 62. [MEDIUM] [AI] Hardcoded Path Default

**Category:** Input Validation

**Description:** The scan command uses a default path of '.' (current directory) which could lead to unintended directory scanning if not explicitly specified.

**Location:** `shared/src/cli.py:54`

---

### 63. [MEDIUM] [AI] Insecure Default Configuration

**Category:** Configuration Management

**Description:** The config parameter is optional and not enforced, which could lead to insecure default configurations being used.

**Location:** `shared/src/cli.py:55`

---

### 64. [HIGH] [AI] Unvalidated User Input

**Category:** Input Validation

**Description:** The URL parameter in the test command is not validated for proper URL format before being used.

**Location:** `shared/src/cli.py:15`

---

### 65. [MEDIUM] [AI] Insecure File Handling

**Category:** File Handling

**Description:** The output and config parameters accept file paths without validation, which could lead to directory traversal or other file system attacks.

**Location:** `shared/src/cli.py:16`

---

### 66. [MEDIUM] [AI] Insecure Default Headless Mode

**Category:** Configuration Management

**Description:** The headless mode is enabled by default, which might not be appropriate for all environments and could lead to unexpected behavior.

**Location:** `shared/src/cli.py:17`

---

### 67. [MEDIUM] [AI] Incomplete Error Handling

**Category:** Error Handling

**Description:** The code does not handle potential exceptions that might occur during file operations or network requests.

**Location:** `shared/src/cli.py`

---

### 68. [MEDIUM] [AI] Insecure Default Compliance

**Category:** Configuration Management

**Description:** The compliance parameter is optional and not enforced, which could lead to non-compliant scans if not explicitly specified.

**Location:** `shared/src/cli.py:60`

---

### 69. [MEDIUM] [AI] Insecure Default Checks

**Category:** Configuration Management

**Description:** The checks parameter is optional and not enforced, which could lead to incomplete security scans if not explicitly specified.

**Location:** `shared/src/cli.py:59`

---

### 70. [HIGH] [AI] Hardcoded API Keys

**Category:** Security Misconfiguration

**Description:** The code hardcodes API keys for various LLM providers, which could lead to unauthorized access and potential misuse of these credentials.

**Location:** `shared/src/llm_client.py:50`

---

### 71. [MEDIUM] [AI] Potential Input Injection Vulnerability

**Category:** Code Injection

**Description:** The `query` and `query_all` methods accept user-provided input (prompt and system_prompt) without any input validation, which could lead to code injection vulnerabilities if the input is not properly sanitized.

**Location:** `shared/src/llm_client.py:98`

---

### 72. [HIGH] [AI] Exposure of API Keys

**Category:** Configuration Management

**Description:** The code retrieves API keys from environment variables without validation or fallback, which could lead to exposure of credentials if the environment variables are improperly configured or leaked.

**Location:** `shared/src/llm_client.py:34`

---

### 73. [MEDIUM] [AI] No Rate Limiting or Throttling Mechanism

**Category:** Denial of Service

**Description:** The application lacks rate limiting or throttling mechanisms for queries to multiple LLM providers, which could lead to overloading the services and potential denial of service.

**Location:** `shared/src/llm_client.py:77`

---

### 74. [MEDIUM] [AI] Potential for Incomplete Error Handling

**Category:** Error Handling

**Description:** The `query_all` method gathers results but ignores exceptions by filtering them out, which may lead to incomplete error handling or undetected failures in the queries.

**Location:** `shared/src/llm_client.py:65`

---

### 75. [MEDIUM] [AI] Lack of Input Validation

**Category:** Input Validation

**Description:** User input in the `prompt` and `system_prompt` parameters is not validated, which may allow injection attacks or other security issues.

**Location:** `shared/src/llm_client.py:50`

---

### 76. [HIGH] [AI] Hardcoded API URLs

**Category:** Configuration

**Description:** The Grok client uses a hardcoded base URL (https://api.x.ai/v1) which could become invalid if the API endpoint changes or if the service is deprecated.

**Location:** `shared/src/llm_client.py:52`

---

### 77. [MEDIUM] [AI] Environment Variables Without Validation

**Category:** Configuration

**Description:** API keys are read directly from environment variables without any validation or fallback mechanism. If the environment variables are not set, the application will fail silently or raise an exception.

**Location:** `shared/src/llm_client.py:30`

---

### 78. [MEDIUM] [AI] Exception Handling in Parallel Queries

**Category:** Error Handling

**Description:** The query_all method gathers exceptions but does not handle or log them, which could lead to undetected failures in parallel queries.

**Location:** `shared/src/llm_client.py:65`

---

### 79. [MEDIUM] [AI] No Rate Limiting

**Category:** Performance

**Description:** The client does not implement any rate limiting, which could lead to excessive API calls and potential denial of service or cost overruns.

**Location:** `shared/src/llm_client.py`

---

### 80. [MEDIUM] [AI] No Input Sanitization

**Category:** Input Validation

**Description:** The prompt and system_prompt parameters are not sanitized before being passed to the LLM providers, which could lead to injection attacks or unexpected behavior.

**Location:** `shared/src/llm_client.py`

---

### 81. [MEDIUM] [AI] No Timeout Configuration

**Category:** Performance

**Description:** The client does not configure timeouts for API calls, which could lead to hanging requests and resource exhaustion.

**Location:** `shared/src/llm_client.py`

---

### 82. [LOW] [AI] Hardcoded Model Names

**Category:** Configuration

**Description:** Model names are hardcoded (e.g., 'gemini-2.0-flash-exp'), which could become invalid if the models are deprecated or renamed.

**Location:** `shared/src/llm_client.py:45`

---

