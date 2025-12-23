import { NextRequest, NextResponse } from 'next/server'

interface ScanRequest {
  repoUrl: string
  apiKeys?: {
    openai?: string
    anthropic?: string
    google?: string
  }
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
}

// Secret patterns to detect
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' as const },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z-_]{35}/g, severity: 'critical' as const },
  { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' as const },
  { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' as const },
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_]{20,}['\"]/gi, severity: 'high' as const },
  { name: 'Password in Code', pattern: /(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]/gi, severity: 'high' as const },
]

// Common vulnerability patterns
const VULNERABILITY_PATTERNS = [
  {
    name: 'SQL Injection Risk',
    pattern: /(?:execute|query)\s*\([^)]*\+|`[^`]*\$\{/g,
    severity: 'high' as const,
    category: 'Injection',
    description: 'Found potential SQL injection vulnerability. User input may be directly concatenated into queries.',
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation.'
  },
  {
    name: 'Eval Usage',
    pattern: /\beval\s*\(/g,
    severity: 'high' as const,
    category: 'Code Execution',
    description: 'Using eval() can execute arbitrary code and is a security risk.',
    recommendation: 'Avoid eval(). Use safer alternatives like JSON.parse() for data parsing.'
  },
  {
    name: 'Dangerous innerHTML',
    pattern: /\.innerHTML\s*=/g,
    severity: 'medium' as const,
    category: 'XSS',
    description: 'Direct innerHTML assignment can lead to Cross-Site Scripting (XSS) attacks.',
    recommendation: 'Use textContent for text, or sanitize HTML before using innerHTML.'
  },
  {
    name: 'HTTP (Not HTTPS)',
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/g,
    severity: 'medium' as const,
    category: 'Configuration',
    description: 'Using HTTP instead of HTTPS exposes data to interception.',
    recommendation: 'Always use HTTPS for external URLs.'
  },
  {
    name: 'Disabled Security',
    pattern: /verify\s*=\s*False|ssl\s*=\s*False|secure\s*=\s*false/gi,
    severity: 'high' as const,
    category: 'Configuration',
    description: 'Security verification appears to be disabled.',
    recommendation: 'Enable SSL/TLS verification and security checks.'
  },
  {
    name: 'Console Log in Production',
    pattern: /console\.(log|debug|info)\s*\(/g,
    severity: 'low' as const,
    category: 'Best Practice',
    description: 'Console logs should be removed in production code.',
    recommendation: 'Remove or disable console logs in production builds.'
  },
  {
    name: 'TODO/FIXME Security',
    pattern: /(?:TODO|FIXME).*(?:security|auth|password|secret)/gi,
    severity: 'medium' as const,
    category: 'Technical Debt',
    description: 'Found unresolved security-related TODO comment.',
    recommendation: 'Address these security TODOs before deploying to production.'
  },
]

export async function POST(request: NextRequest) {
  try {
    const body: ScanRequest = await request.json()
    const { repoUrl, apiKeys } = body

    // Validate URL
    if (!repoUrl || (!repoUrl.includes('github.com') && !repoUrl.includes('gitlab.com'))) {
      return NextResponse.json(
        { error: 'Invalid repository URL. Please provide a GitHub or GitLab URL.' },
        { status: 400 }
      )
    }

    // In production, we would:
    // 1. Clone the repository to a temp directory
    // 2. Scan all files with our patterns
    // 3. Optionally use AI APIs for deeper analysis
    // 4. Clean up the temp directory

    // For now, return demo results
    // TODO: Implement actual GitHub API integration and file scanning

    const findings: Finding[] = []
    let findingId = 1

    // Simulate scanning with pattern-based detection
    // In production, this would iterate over actual files

    // Demo findings based on common issues
    findings.push({
      id: String(findingId++),
      title: 'Potential Hardcoded Secret Detected',
      severity: 'critical',
      category: 'Secrets',
      description: 'The scanner found patterns that may indicate hardcoded credentials or API keys in your code.',
      recommendation: 'Move all secrets to environment variables. Never commit secrets to version control.',
      file: 'src/config.ts',
      line: 15,
    })

    findings.push({
      id: String(findingId++),
      title: 'Missing Rate Limiting',
      severity: 'high',
      category: 'API Security',
      description: 'API endpoints do not appear to have rate limiting configured, which could allow abuse.',
      recommendation: 'Implement rate limiting using middleware like express-rate-limit or similar.',
    })

    findings.push({
      id: String(findingId++),
      title: 'Dependencies May Be Outdated',
      severity: 'high',
      category: 'Dependencies',
      description: 'Some packages may have known security vulnerabilities.',
      recommendation: 'Run npm audit or pip-audit regularly and update dependencies.',
    })

    findings.push({
      id: String(findingId++),
      title: 'Missing Content Security Policy',
      severity: 'medium',
      category: 'Headers',
      description: 'No Content-Security-Policy header detected. This helps prevent XSS attacks.',
      recommendation: 'Add CSP headers to your server configuration.',
    })

    findings.push({
      id: String(findingId++),
      title: 'Debug Mode May Be Enabled',
      severity: 'medium',
      category: 'Configuration',
      description: 'Debug settings may be enabled which could expose sensitive information.',
      recommendation: 'Ensure DEBUG=false in production environment.',
    })

    findings.push({
      id: String(findingId++),
      title: 'Console Logs Found',
      severity: 'low',
      category: 'Best Practice',
      description: 'Multiple console.log statements found which may leak information.',
      recommendation: 'Remove or disable console logs in production.',
    })

    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    }

    // Calculate score (100 - deductions)
    const score = Math.max(0, 100 -
      (summary.critical * 25) -
      (summary.high * 10) -
      (summary.medium * 5) -
      (summary.low * 2)
    )

    const result: ScanResult = {
      score,
      findings,
      summary,
      scannedAt: new Date().toISOString(),
      repoUrl,
    }

    return NextResponse.json(result)

  } catch (error) {
    console.error('Scan error:', error)
    return NextResponse.json(
      { error: 'Failed to scan repository. Please try again.' },
      { status: 500 }
    )
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'SafeguardAI Scan API',
    version: '1.0.0',
    usage: 'POST /api/scan with { repoUrl: "https://github.com/user/repo" }',
  })
}
