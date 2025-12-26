import { NextRequest, NextResponse } from 'next/server'

interface ScanRequest {
  repoUrl: string
  apiKeys?: {
    anthropic?: string
    openai?: string
    gemini?: string
    grok?: string
    mistral?: string
  }
  githubToken?: string
}

interface LLMFinding {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  description: string
  file?: string
  line?: number
  source?: string
}

interface LLMResult {
  provider: string
  success: boolean
  error?: string
  findings: LLMFinding[]
}

// Shared prompt for all LLM analysis - reduces false positives
const getSecurityPrompt = (filePath: string, code: string) => `Analyze this code for REAL security vulnerabilities only. Return a JSON array of findings.

IMPORTANT - DO NOT flag these as issues (they are false positives):
- localStorage usage for user-provided API keys/tokens in client-side tools (this is intentional - tokens stay in user's browser)
- React/Next.js standard patterns like {children} props, metadata exports, layout components
- Auto-generated framework files (next-env.d.ts, .d.ts files, config files)
- Static metadata or constants defined in code
- Empty catch blocks that handle expected parse failures
- Markdown generation for file downloads (not rendered in browser)
- Client-side-only applications where data never leaves the browser

ONLY flag REAL exploitable vulnerabilities like:
- SQL injection, command injection, code injection
- XSS where user input is actually rendered unsanitized
- Hardcoded secrets/passwords/API keys IN THE CODE (not user-provided)
- Insecure cryptography or authentication bypasses
- Path traversal, SSRF, or file inclusion vulnerabilities
- Exposed sensitive endpoints without authentication

Each finding must have: title (string), severity (critical|high|medium|low), category (string), description (string), line (number if applicable).

File: ${filePath}
\`\`\`
${code.slice(0, 4000)}
\`\`\`

Return [] if no REAL issues found. Return ONLY valid JSON array, no other text.`

// LLM analysis functions
async function analyzeWithAnthropic(code: string, filePath: string, apiKey: string): Promise<LLMResult> {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-3-haiku-20240307',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: getSecurityPrompt(filePath, code)
        }],
      }),
    })

    if (!response.ok) {
      return { provider: 'anthropic', success: false, error: `API error: ${response.status}`, findings: [] }
    }
    const data = await response.json()
    const text = data.content?.[0]?.text || '[]'
    const jsonMatch = text.match(/\[[\s\S]*\]/)
    if (!jsonMatch) return { provider: 'anthropic', success: true, findings: [] }
    const findings = JSON.parse(jsonMatch[0])
    return { provider: 'anthropic', success: true, findings: findings.map((f: LLMFinding) => ({ ...f, file: filePath, source: 'Claude' })) }
  } catch (e) {
    return { provider: 'anthropic', success: false, error: e instanceof Error ? e.message : 'Unknown error', findings: [] }
  }
}

async function analyzeWithOpenAI(code: string, filePath: string, apiKey: string): Promise<LLMResult> {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: getSecurityPrompt(filePath, code)
        }],
      }),
    })

    if (!response.ok) {
      return { provider: 'openai', success: false, error: `API error: ${response.status}`, findings: [] }
    }
    const data = await response.json()
    const text = data.choices?.[0]?.message?.content || '[]'
    const jsonMatch = text.match(/\[[\s\S]*\]/)
    if (!jsonMatch) return { provider: 'openai', success: true, findings: [] }
    const findings = JSON.parse(jsonMatch[0])
    return { provider: 'openai', success: true, findings: findings.map((f: LLMFinding) => ({ ...f, file: filePath, source: 'GPT' })) }
  } catch (e) {
    return { provider: 'openai', success: false, error: e instanceof Error ? e.message : 'Unknown error', findings: [] }
  }
}

async function analyzeWithGemini(code: string, filePath: string, apiKey: string): Promise<LLMResult> {
  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: getSecurityPrompt(filePath, code)
          }]
        }],
      }),
    })

    if (!response.ok) {
      const errorText = await response.text().catch(() => '')
      return { provider: 'gemini', success: false, error: `API error ${response.status}: ${errorText.slice(0, 100)}`, findings: [] }
    }
    const data = await response.json()
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '[]'
    const jsonMatch = text.match(/\[[\s\S]*\]/)
    if (!jsonMatch) return { provider: 'gemini', success: true, findings: [] }
    const findings = JSON.parse(jsonMatch[0])
    return { provider: 'gemini', success: true, findings: findings.map((f: LLMFinding) => ({ ...f, file: filePath, source: 'Gemini' })) }
  } catch (e) {
    return { provider: 'gemini', success: false, error: e instanceof Error ? e.message : 'Unknown error', findings: [] }
  }
}

async function analyzeWithGrok(code: string, filePath: string, apiKey: string): Promise<LLMResult> {
  try {
    const response = await fetch('https://api.x.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'grok-2-1212',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: getSecurityPrompt(filePath, code)
        }],
      }),
    })

    if (!response.ok) {
      const errorText = await response.text().catch(() => '')
      return { provider: 'grok', success: false, error: `API error ${response.status}: ${errorText.slice(0, 100)}`, findings: [] }
    }
    const data = await response.json()
    const text = data.choices?.[0]?.message?.content || '[]'
    const jsonMatch = text.match(/\[[\s\S]*\]/)
    if (!jsonMatch) return { provider: 'grok', success: true, findings: [] }
    const findings = JSON.parse(jsonMatch[0])
    return { provider: 'grok', success: true, findings: findings.map((f: LLMFinding) => ({ ...f, file: filePath, source: 'Grok' })) }
  } catch (e) {
    return { provider: 'grok', success: false, error: e instanceof Error ? e.message : 'Unknown error', findings: [] }
  }
}

async function analyzeWithMistral(code: string, filePath: string, apiKey: string): Promise<LLMResult> {
  try {
    const response = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'mistral-small-latest',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: getSecurityPrompt(filePath, code)
        }],
      }),
    })

    if (!response.ok) {
      return { provider: 'mistral', success: false, error: `API error: ${response.status}`, findings: [] }
    }
    const data = await response.json()
    const text = data.choices?.[0]?.message?.content || '[]'
    const jsonMatch = text.match(/\[[\s\S]*\]/)
    if (!jsonMatch) return { provider: 'mistral', success: true, findings: [] }
    const findings = JSON.parse(jsonMatch[0])
    return { provider: 'mistral', success: true, findings: findings.map((f: LLMFinding) => ({ ...f, file: filePath, source: 'Mistral' })) }
  } catch (e) {
    return { provider: 'mistral', success: false, error: e instanceof Error ? e.message : 'Unknown error', findings: [] }
  }
}

type ApiKeys = NonNullable<ScanRequest['apiKeys']>

interface LLMAnalysisResult {
  findings: LLMFinding[]
  status: { provider: string; success: boolean; error?: string }[]
}

async function runLLMAnalysis(code: string, filePath: string, apiKeys: ApiKeys): Promise<LLMAnalysisResult> {
  const analyses: Promise<LLMResult>[] = []

  if (apiKeys.anthropic) analyses.push(analyzeWithAnthropic(code, filePath, apiKeys.anthropic))
  if (apiKeys.openai) analyses.push(analyzeWithOpenAI(code, filePath, apiKeys.openai))
  if (apiKeys.gemini) analyses.push(analyzeWithGemini(code, filePath, apiKeys.gemini))
  if (apiKeys.grok) analyses.push(analyzeWithGrok(code, filePath, apiKeys.grok))
  if (apiKeys.mistral) analyses.push(analyzeWithMistral(code, filePath, apiKeys.mistral))

  if (analyses.length === 0) return { findings: [], status: [] }

  const results = await Promise.all(analyses)

  const findings = results.flatMap(r => r.findings)
  const status = results.map(r => ({ provider: r.provider, success: r.success, error: r.error }))

  return { findings, status }
}

interface Finding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  description: string
  recommendation: string
  file?: string
  line?: number
  match?: string
  source?: string
}

interface ScanResult {
  score: number
  findings: Finding[]
  summary: {
    critical: number
    high: number
    medium: number
    low: number
  }
  scannedAt: string
  repoUrl: string
  filesScanned: number
  llmStatus?: { provider: string; success: boolean; error?: string }[]
}

// Secret patterns to detect
const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'AWS Access Key ID detected. This could allow unauthorized access to AWS resources.',
    recommendation: 'Remove this key immediately, rotate it in AWS IAM, and use environment variables instead.'
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]/gi,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'AWS Secret Access Key detected.',
    recommendation: 'Remove and rotate this key immediately. Use AWS Secrets Manager or environment variables.'
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'GitHub Personal Access Token detected.',
    recommendation: 'Revoke this token in GitHub settings and use environment variables for tokens.'
  },
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z-_]{35}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Google API Key detected.',
    recommendation: 'Restrict this key in Google Cloud Console and move to environment variables.'
  },
  {
    name: 'Stripe Live Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Stripe live secret key detected. This could allow unauthorized payments.',
    recommendation: 'Rotate this key immediately in Stripe Dashboard. Never commit live keys.'
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'medium' as const,
    category: 'Secrets',
    description: 'Stripe live publishable key in code. While less sensitive, consider using env vars.',
    recommendation: 'Move to environment variables for better security hygiene.'
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Private key detected in code.',
    recommendation: 'Remove immediately. Private keys should never be in source control.'
  },
  {
    name: 'Generic API Key Assignment',
    pattern: /(?:api[_-]?key|apikey|api_secret|apisecret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_]{20,}['\"]/gi,
    severity: 'high' as const,
    category: 'Secrets',
    description: 'Potential API key or secret hardcoded in source.',
    recommendation: 'Move all API keys to environment variables.'
  },
  {
    name: 'Password Assignment',
    pattern: /(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]/gi,
    severity: 'high' as const,
    category: 'Secrets',
    description: 'Hardcoded password or secret detected.',
    recommendation: 'Never hardcode passwords. Use environment variables or a secrets manager.'
  },
  {
    name: 'JWT Secret',
    pattern: /(?:jwt[_-]?secret|token[_-]?secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]/gi,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'JWT secret key hardcoded. Attackers could forge tokens.',
    recommendation: 'Move JWT secrets to environment variables and rotate immediately.'
  },
  {
    name: 'Database URL with Credentials',
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/gi,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Database connection string with credentials detected.',
    recommendation: 'Use environment variables for database URLs. Rotate credentials if exposed.'
  },
  {
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{32,}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'OpenAI API key detected.',
    recommendation: 'Rotate this key in OpenAI dashboard and use environment variables.'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Slack API token detected.',
    recommendation: 'Revoke and regenerate this token in Slack API settings.'
  },
  {
    name: 'Discord Token',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: 'critical' as const,
    category: 'Secrets',
    description: 'Discord bot token detected.',
    recommendation: 'Regenerate this token immediately in Discord Developer Portal.'
  },
]

// Vulnerability patterns
const VULNERABILITY_PATTERNS = [
  {
    name: 'SQL Injection Risk',
    pattern: /(?:execute|query|raw)\s*\(\s*[`'"][^`'"]*\s*\+|\+\s*[^`'"]*[`'"]\s*\)/g,
    severity: 'high' as const,
    category: 'Injection',
    description: 'Potential SQL injection vulnerability. User input may be concatenated into queries.',
    recommendation: 'Use parameterized queries or an ORM. Never concatenate user input into SQL.'
  },
  {
    name: 'Command Injection Risk',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[`'"][^`'"]*\s*\+|\$\{)/g,
    severity: 'critical' as const,
    category: 'Injection',
    description: 'Potential command injection. User input may be passed to shell commands.',
    recommendation: 'Avoid exec/spawn with user input. Use libraries with safe APIs instead.'
  },
  {
    name: 'Eval Usage',
    pattern: /\beval\s*\(/g,
    severity: 'high' as const,
    category: 'Code Execution',
    description: 'eval() executes arbitrary code and is a major security risk.',
    recommendation: 'Avoid eval(). Use JSON.parse() for data or safer alternatives.'
  },
  {
    name: 'Function Constructor',
    pattern: /new\s+Function\s*\(/g,
    severity: 'high' as const,
    category: 'Code Execution',
    description: 'new Function() is similar to eval() and can execute arbitrary code.',
    recommendation: 'Avoid dynamic code execution. Refactor to use static code paths.'
  },
  {
    name: 'Dangerous innerHTML',
    pattern: /\.innerHTML\s*=(?!\s*['"`])/g,
    severity: 'medium' as const,
    category: 'XSS',
    description: 'innerHTML with dynamic content can lead to XSS attacks.',
    recommendation: 'Use textContent for text, or sanitize with DOMPurify before using innerHTML.'
  },
  {
    name: 'dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML/g,
    severity: 'medium' as const,
    category: 'XSS',
    description: 'React dangerouslySetInnerHTML can lead to XSS if content is not sanitized.',
    recommendation: 'Sanitize content with DOMPurify before using dangerouslySetInnerHTML.'
  },
  {
    name: 'document.write',
    pattern: /document\.write\s*\(/g,
    severity: 'medium' as const,
    category: 'XSS',
    description: 'document.write() can be exploited for XSS attacks.',
    recommendation: 'Use DOM manipulation methods instead of document.write().'
  },
  {
    name: 'HTTP URLs',
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"]/g,
    severity: 'medium' as const,
    category: 'Configuration',
    description: 'HTTP URLs are insecure. Data can be intercepted.',
    recommendation: 'Always use HTTPS for external resources.'
  },
  {
    name: 'Disabled SSL/TLS Verification',
    pattern: /(?:rejectUnauthorized|verify|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:false|0|False)/gi,
    severity: 'high' as const,
    category: 'Configuration',
    description: 'SSL/TLS verification is disabled, allowing man-in-the-middle attacks.',
    recommendation: 'Enable SSL verification. Fix certificate issues properly.'
  },
  {
    name: 'Weak Crypto',
    pattern: /(?:createCipher|MD5|SHA1)\s*\(/gi,
    severity: 'high' as const,
    category: 'Cryptography',
    description: 'Weak or deprecated cryptographic algorithm detected.',
    recommendation: 'Use modern algorithms: AES-256-GCM, SHA-256 or better.'
  },
  {
    name: 'Hardcoded IP Address',
    pattern: /['"](?:\d{1,3}\.){3}\d{1,3}(?::\d+)?['"]/g,
    severity: 'low' as const,
    category: 'Configuration',
    description: 'Hardcoded IP address found. This reduces flexibility.',
    recommendation: 'Use environment variables or configuration files for IP addresses.'
  },
  {
    name: 'CORS Wildcard',
    pattern: /(?:Access-Control-Allow-Origin|cors)['":\s]+['"]\*['"]/gi,
    severity: 'medium' as const,
    category: 'Configuration',
    description: 'CORS is configured to allow all origins, which may be too permissive.',
    recommendation: 'Restrict CORS to specific trusted origins.'
  },
  {
    name: 'Console Logging',
    pattern: /(?<!https?:\/\/[^\s]*?)console\.(log|debug|info|warn|error)\s*\(/g,
    severity: 'low' as const,
    category: 'Best Practice',
    description: 'Console statements may leak sensitive information in production.',
    recommendation: 'Remove console statements or use a proper logging library.'
  },
  {
    name: 'TODO Security Comment',
    pattern: /(?:TODO|FIXME|HACK|XXX).*(?:security|auth|password|secret|vulnerable|exploit)/gi,
    severity: 'medium' as const,
    category: 'Technical Debt',
    description: 'Unresolved security-related TODO comment found.',
    recommendation: 'Address this security TODO before deploying to production.'
  },
  {
    name: 'Disabled ESLint Security',
    pattern: /eslint-disable.*(?:security|no-eval)/gi,
    severity: 'medium' as const,
    category: 'Configuration',
    description: 'Security-related ESLint rules are disabled.',
    recommendation: 'Enable security linting rules and fix the underlying issues.'
  },
]

// Files to skip
const SKIP_PATTERNS = [
  /node_modules\//,
  /\.git\//,
  /vendor\//,
  /dist\//,
  /build\//,
  /\.next\//,
  /coverage\//,
  /\.min\.(js|css)$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.png$/,
  /\.jpg$/,
  /\.jpeg$/,
  /\.gif$/,
  /\.svg$/,
  /\.ico$/,
  /\.woff2?$/,
  /\.ttf$/,
  /\.eot$/,
  /\.mp[34]$/,
  /\.wav$/,
  /\.pdf$/,
  /\.zip$/,
  /\.tar$/,
  /\.gz$/,
]

// File extensions to scan
const SCAN_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.java', '.go', '.rs',
  '.env', '.json', '.yaml', '.yml', '.toml',
  '.sh', '.bash', '.zsh',
  '.sql', '.graphql',
  '.html', '.htm', '.vue', '.svelte',
  '.config', '.conf', '.ini',
  '.md', '.txt', // Sometimes secrets end up here
]

function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  // Handle various GitHub URL formats
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?(?:\/.*)?$/,
    /github\.com:([^\/]+)\/([^\/]+?)(?:\.git)?$/,
  ]

  for (const pattern of patterns) {
    const match = url.match(pattern)
    if (match) {
      return { owner: match[1], repo: match[2].replace(/\.git$/, '') }
    }
  }
  return null
}

function shouldScanFile(path: string): boolean {
  // Skip certain paths
  if (SKIP_PATTERNS.some(pattern => pattern.test(path))) {
    return false
  }

  // Check if extension should be scanned
  const ext = '.' + path.split('.').pop()?.toLowerCase()
  return SCAN_EXTENSIONS.includes(ext) || path.includes('.env')
}

function getLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length
}

async function fetchRepoTree(owner: string, repo: string, githubToken?: string): Promise<{ path: string; url: string }[]> {
  // Build headers with optional auth
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'VibeCheck-Scanner/1.0',
  }
  if (githubToken) {
    headers['Authorization'] = `Bearer ${githubToken}`
  }

  // Get default branch first
  const repoResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers,
  })

  if (!repoResponse.ok) {
    if (repoResponse.status === 404) {
      throw new Error('Repository not found. Make sure it exists and is public.')
    }
    throw new Error(`GitHub API error: ${repoResponse.status}`)
  }

  const repoData = await repoResponse.json()
  const defaultBranch = repoData.default_branch || 'main'

  // Get the tree
  const treeResponse = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`,
    { headers }
  )

  if (!treeResponse.ok) {
    throw new Error(`Failed to fetch repository tree: ${treeResponse.status}`)
  }

  const treeData = await treeResponse.json()

  // Filter to only files (not directories) that we want to scan
  return treeData.tree
    .filter((item: { type: string; path: string }) =>
      item.type === 'blob' && shouldScanFile(item.path)
    )
    .map((item: { path: string; url: string }) => ({
      path: item.path,
      url: item.url,
    }))
}

async function fetchFileContent(url: string, githubToken?: string): Promise<string> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'VibeCheck-Scanner/1.0',
  }
  if (githubToken) {
    headers['Authorization'] = `Bearer ${githubToken}`
  }

  const response = await fetch(url, { headers })

  if (!response.ok) {
    throw new Error(`Failed to fetch file: ${response.status}`)
  }

  const data = await response.json()

  // GitHub returns base64 encoded content
  if (data.encoding === 'base64') {
    return Buffer.from(data.content, 'base64').toString('utf-8')
  }

  return data.content || ''
}

function isPatternDefinition(content: string, matchIndex: number): boolean {
  // Get the line containing the match
  const lineStart = content.lastIndexOf('\n', matchIndex) + 1
  const lineEnd = content.indexOf('\n', matchIndex)
  const line = content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd)

  // Check if this looks like a pattern/regex definition (not actual code)
  const patternIndicators = [
    /pattern\s*[:=]/i,           // pattern: or pattern =
    /regex\s*[:=]/i,             // regex: or regex =
    /RegExp\s*\(/,               // new RegExp(
    /\/[^\/]+\/[gimsuvy]*\s*,/,  // /pattern/, (regex literal followed by comma)
    /name\s*:\s*['"][^'"]+['"]/,  // name: 'Something' (pattern config)
    /description\s*:\s*['"][^'"]+['"]/, // description in pattern config
    /severity\s*:\s*['"][^'"]+['"]/, // severity in pattern config
    /recommendation\s*:\s*['"][^'"]+['"]/, // recommendation
    /const\s+\w+_PATTERNS\s*=/,  // const SECRET_PATTERNS =
    /category\s*:\s*['"][^'"]+['"]/, // category in pattern config
  ]

  for (const indicator of patternIndicators) {
    if (indicator.test(line)) {
      return true
    }
  }

  // Check if match is inside a regex literal on this line
  // Count unescaped forward slashes before the match position within the line
  const beforeMatch = line.substring(0, matchIndex - lineStart)
  const slashCount = (beforeMatch.match(/(?<!\\)\//g) || []).length
  if (slashCount % 2 === 1) {
    // Odd number of slashes means we're inside a regex literal
    return true
  }

  return false
}

function scanContent(content: string, filePath: string, findings: Finding[], findingId: { value: number }) {
  // Check for secrets
  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)
    let match
    while ((match = regex.exec(content)) !== null) {
      // Skip if it looks like a placeholder or example
      const matchText = match[0]
      if (matchText.includes('xxx') || matchText.includes('XXX') ||
          matchText.includes('your_') || matchText.includes('YOUR_') ||
          matchText.includes('example') || matchText.includes('EXAMPLE') ||
          matchText.includes('placeholder') || matchText.includes('<') ||
          matchText.includes('${')) {
        continue
      }

      // Skip if this is a pattern definition (not actual code)
      if (isPatternDefinition(content, match.index)) {
        continue
      }

      findings.push({
        id: String(findingId.value++),
        title: pattern.name,
        severity: pattern.severity,
        category: pattern.category,
        description: pattern.description,
        recommendation: pattern.recommendation,
        file: filePath,
        line: getLineNumber(content, match.index),
        match: matchText.substring(0, 50) + (matchText.length > 50 ? '...' : ''),
      })
    }
  }

  // Check for vulnerabilities
  for (const pattern of VULNERABILITY_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)
    let match
    // Limit logging findings to first 3
    let patternCount = 0
    const maxPerPattern = pattern.name === 'Console Logging' ? 3 : 10

    while ((match = regex.exec(content)) !== null && patternCount < maxPerPattern) {
      // Skip if this is a pattern definition (not actual code)
      if (isPatternDefinition(content, match.index)) {
        continue
      }

      patternCount++
      findings.push({
        id: String(findingId.value++),
        title: pattern.name,
        severity: pattern.severity,
        category: pattern.category,
        description: pattern.description,
        recommendation: pattern.recommendation,
        file: filePath,
        line: getLineNumber(content, match.index),
      })
    }
  }
}

async function analyzeDependencies(owner: string, repo: string, findings: Finding[], findingId: { value: number }, githubToken?: string) {
  // Build headers with optional auth
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'VibeCheck-Scanner/1.0',
  }
  if (githubToken) {
    headers['Authorization'] = `Bearer ${githubToken}`
  }

  // Check for package.json
  try {
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/package.json`,
      { headers }
    )

    if (response.ok) {
      const data = await response.json()
      const content = Buffer.from(data.content, 'base64').toString('utf-8')
      const pkg = JSON.parse(content)

      // Check for known vulnerable patterns
      const deps = { ...pkg.dependencies, ...pkg.devDependencies }

      // Very outdated or vulnerable packages (examples)
      const knownVulnerable: Record<string, string> = {
        'lodash': '4.17.20', // CVEs below this
        'axios': '0.21.1', // SSRF below this
        'express': '4.17.0', // Various below this
        'jsonwebtoken': '8.5.1', // Various below this
      }

      for (const [pkg, minVersion] of Object.entries(knownVulnerable)) {
        if (deps[pkg]) {
          const version = deps[pkg].replace(/[\^~>=<]/g, '')
          // Simple version comparison (not perfect but catches obvious issues)
          if (version && version < minVersion) {
            findings.push({
              id: String(findingId.value++),
              title: `Potentially Vulnerable: ${pkg}`,
              severity: 'high',
              category: 'Dependencies',
              description: `${pkg}@${deps[pkg]} may have known vulnerabilities.`,
              recommendation: `Run 'npm audit' and update ${pkg} to the latest version.`,
              file: 'package.json',
            })
          }
        }
      }
    }
  } catch (e) {
    // Ignore package.json errors
  }
}

export async function POST(request: NextRequest) {
  try {
    const body: ScanRequest = await request.json()
    const { repoUrl, apiKeys, githubToken } = body

    // Parse GitHub URL
    const parsed = parseGitHubUrl(repoUrl)
    if (!parsed) {
      return NextResponse.json(
        { error: 'Invalid repository URL. Please provide a valid GitHub URL (e.g., https://github.com/owner/repo)' },
        { status: 400 }
      )
    }

    const { owner, repo } = parsed
    const findings: Finding[] = []
    const findingId = { value: 1 }
    let filesScanned = 0
    let llmStatus: { provider: string; success: boolean; error?: string }[] = []

    try {
      // Fetch repo tree
      const files = await fetchRepoTree(owner, repo, githubToken)

      // Limit files to scan (avoid timeout)
      const filesToScan = files.slice(0, 100)

      // Scan each file
      const hasApiKeys = apiKeys && Object.values(apiKeys).some(k => k)
      const llmFilesToAnalyze: { path: string; content: string }[] = []

      for (const file of filesToScan) {
        try {
          const content = await fetchFileContent(file.url, githubToken)
          scanContent(content, file.path, findings, findingId)
          filesScanned++

          // Collect important files for LLM analysis (limit to key files to avoid API costs)
          if (hasApiKeys && llmFilesToAnalyze.length < 10) {
            const ext = file.path.split('.').pop()?.toLowerCase()
            const isImportant = ['ts', 'tsx', 'js', 'jsx', 'py', 'go', 'java', 'rb', 'php'].includes(ext || '')
            const isRoute = file.path.includes('route') || file.path.includes('api') || file.path.includes('auth')
            const isConfig = file.path.includes('.env') || file.path.includes('config')

            // Skip non-production files and framework files from AI analysis
            const isExcluded = file.path.includes('scan') ||
              file.path.includes('security') ||
              file.path.includes('pattern') ||
              file.path.includes('vuln') ||
              file.path.includes('detector') ||
              file.path.includes('analyzer') ||
              file.path.includes('checker') ||
              file.path.includes('test') ||
              file.path.includes('spec') ||
              file.path.includes('mock') ||
              file.path.includes('fixture') ||
              file.path.includes('example') ||
              file.path.includes('sample') ||
              file.path.includes('demo') ||
              file.path.includes('cli.') ||
              file.path.includes('shared/') ||
              file.path.includes('flow') ||
              file.path.includes('tsconfig') ||
              file.path.includes('tailwind.config') ||
              file.path.includes('postcss.config') ||
              file.path.includes('next.config') ||
              file.path.includes('eslint') ||
              file.path.includes('prettier') ||
              file.path.includes('.config.') ||
              // Framework/auto-generated files
              file.path.includes('next-env.d.ts') ||
              file.path.endsWith('.d.ts') ||
              file.path.includes('layout.tsx') ||
              file.path.includes('layout.ts')

            if ((isImportant || isRoute || isConfig) && !isExcluded) {
              llmFilesToAnalyze.push({ path: file.path, content })
            }
          }
        } catch (e) {
          // Skip files that can't be read
        }
      }

      // Run LLM analysis on collected files (in parallel)
      if (hasApiKeys && llmFilesToAnalyze.length > 0 && apiKeys) {
        const llmPromises = llmFilesToAnalyze.map(f => runLLMAnalysis(f.content, f.path, apiKeys))
        const llmResults = await Promise.all(llmPromises)

        // Collect all findings
        const allLlmFindings = llmResults.flatMap(r => r.findings)

        // Aggregate status across all files (dedupe by provider, mark failed if any failed)
        const statusMap = new Map<string, { success: boolean; error?: string }>()
        for (const result of llmResults) {
          for (const s of result.status) {
            const existing = statusMap.get(s.provider)
            if (!existing) {
              statusMap.set(s.provider, { success: s.success, error: s.error })
            } else if (!s.success) {
              // If any call failed, mark as failed
              statusMap.set(s.provider, { success: false, error: s.error })
            }
          }
        }
        llmStatus = Array.from(statusMap.entries()).map(([provider, status]) => ({
          provider,
          success: status.success,
          error: status.error,
        }))

        // Add LLM findings with unique IDs
        for (const llmFinding of allLlmFindings) {
          findings.push({
            id: String(findingId.value++),
            title: `[AI] ${llmFinding.title}`,
            severity: llmFinding.severity,
            category: llmFinding.category,
            description: llmFinding.description,
            recommendation: 'AI-detected issue. Review and verify this finding.',
            file: llmFinding.file,
            line: llmFinding.line,
            source: llmFinding.source,
          })
        }
      }

      // Check dependencies
      await analyzeDependencies(owner, repo, findings, findingId, githubToken)

      // If we had to limit files, add a note
      if (files.length > 100) {
        findings.push({
          id: String(findingId.value++),
          title: 'Partial Scan',
          severity: 'low',
          category: 'Info',
          description: `Repository has ${files.length} scannable files. Only first 100 were scanned to avoid timeout.`,
          recommendation: 'For complete analysis, run a local scan or use the CLI tool.',
        })
      }

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      return NextResponse.json(
        { error: `Failed to scan repository: ${errorMessage}` },
        { status: 400 }
      )
    }

    // Deduplicate similar findings (especially AI findings from multiple models)
    const uniqueFindings = findings.reduce((acc: Finding[], finding) => {
      // For console logs, only keep first occurrence per file
      if (finding.title === 'Console Logging') {
        const existing = acc.find(f => f.title === 'Console Logging' && f.file === finding.file)
        if (existing) return acc
      }

      // For AI findings, deduplicate by similar title/category/file
      if (finding.title.startsWith('[AI]') && finding.source) {
        // Normalize title for comparison (remove [AI] prefix and lowercase)
        const normalizedTitle = finding.title.replace('[AI] ', '').toLowerCase()
        const normalizedCategory = finding.category.toLowerCase()

        // Find existing similar finding
        const existing = acc.find(f => {
          if (!f.title.startsWith('[AI]')) return false
          const existingTitle = f.title.replace('[AI] ', '').toLowerCase()
          const existingCategory = f.category.toLowerCase()

          // Match if same category and similar title (or same file)
          const sameTopic = existingCategory === normalizedCategory &&
            (existingTitle.includes(normalizedTitle.slice(0, 20)) ||
             normalizedTitle.includes(existingTitle.slice(0, 20)) ||
             f.file === finding.file)
          return sameTopic
        })

        if (existing && existing.source) {
          // Merge sources
          if (!existing.source.includes(finding.source)) {
            existing.source = `${existing.source}, ${finding.source}`
          }
          return acc
        }
      }

      acc.push(finding)
      return acc
    }, [])

    // Calculate summary
    const summary = {
      critical: uniqueFindings.filter(f => f.severity === 'critical').length,
      high: uniqueFindings.filter(f => f.severity === 'high').length,
      medium: uniqueFindings.filter(f => f.severity === 'medium').length,
      low: uniqueFindings.filter(f => f.severity === 'low').length,
    }

    // Calculate score
    const score = Math.max(0, Math.min(100, 100 -
      (summary.critical * 25) -
      (summary.high * 10) -
      (summary.medium * 5) -
      (summary.low * 2)
    ))

    const result: ScanResult = {
      score,
      findings: uniqueFindings,
      summary,
      scannedAt: new Date().toISOString(),
      repoUrl,
      filesScanned,
      llmStatus: llmStatus.length > 0 ? llmStatus : undefined,
    }

    return NextResponse.json(result)

  } catch {
    return NextResponse.json(
      { error: 'Failed to scan repository. Please try again.' },
      { status: 500 }
    )
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'Vibe Check Security Scanner API',
    version: '2.0.0',
    usage: 'POST /api/scan with { repoUrl: "https://github.com/owner/repo" }',
    features: [
      'Secret detection (AWS, GitHub, Stripe, OpenAI, etc.)',
      'Vulnerability patterns (SQL injection, XSS, eval, etc.)',
      'Dependency analysis',
      'Real-time GitHub repository scanning',
    ],
  })
}
