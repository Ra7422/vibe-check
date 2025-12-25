'use client'

import { useState, useEffect } from 'react'
import { Shield, Github, AlertTriangle, CheckCircle, Lock, Loader2, ArrowRight, Download, Sparkles, ExternalLink, Key } from 'lucide-react'

type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error'

interface Finding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  description: string
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
}

export default function Home() {
  const [step, setStep] = useState<'welcome' | 'setup' | 'scan' | 'results'>('welcome')
  const [repoUrl, setRepoUrl] = useState('')
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [results, setResults] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')

  // GitHub token state (Personal Access Token)
  const [githubToken, setGithubToken] = useState('')

  // LLM API keys state
  const [apiKeys, setApiKeys] = useState({
    anthropic: '',
    openai: '',
    gemini: '',
    grok: '',
    mistral: '',
  })

  // Load stored tokens on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('github_token')
    if (storedToken) {
      setGithubToken(storedToken)
    }
    // Load LLM API keys
    const storedApiKeys = localStorage.getItem('llm_api_keys')
    if (storedApiKeys) {
      try {
        setApiKeys(JSON.parse(storedApiKeys))
      } catch {}
    }
  }, [])

  // Save GitHub token to localStorage when it changes
  const handleGithubTokenChange = (token: string) => {
    setGithubToken(token)
    if (token) {
      localStorage.setItem('github_token', token)
    } else {
      localStorage.removeItem('github_token')
    }
  }

  // Save LLM API key to localStorage
  const handleApiKeyChange = (provider: keyof typeof apiKeys, key: string) => {
    const newKeys = { ...apiKeys, [provider]: key }
    setApiKeys(newKeys)
    localStorage.setItem('llm_api_keys', JSON.stringify(newKeys))
  }

  // LLM providers config
  const llmProviders = [
    { id: 'anthropic', name: 'Anthropic (Claude)', placeholder: 'sk-ant-...', url: 'https://console.anthropic.com/settings/keys' },
    { id: 'openai', name: 'OpenAI (GPT)', placeholder: 'sk-...', url: 'https://platform.openai.com/api-keys' },
    { id: 'gemini', name: 'Google (Gemini)', placeholder: 'AI...', url: 'https://aistudio.google.com/app/apikey' },
    { id: 'grok', name: 'xAI (Grok)', placeholder: 'xai-...', url: 'https://console.x.ai/' },
    { id: 'mistral', name: 'Mistral', placeholder: 'M...', url: 'https://console.mistral.ai/api-keys' },
  ] as const

  // Generate markdown report
  const generateReport = () => {
    if (!results) return ''

    let md = `# Security Scan Report\n\n`
    md += `**Repository:** ${repoUrl}\n`
    md += `**Score:** ${results.score}/100\n`
    md += `**Date:** ${new Date().toISOString().split('T')[0]}\n\n`

    md += `## Summary\n\n`
    md += `| Severity | Count |\n`
    md += `|----------|-------|\n`
    md += `| Critical | ${results.summary.critical} |\n`
    md += `| High | ${results.summary.high} |\n`
    md += `| Medium | ${results.summary.medium} |\n`
    md += `| Low | ${results.summary.low} |\n\n`

    md += `## Issues to Fix\n\n`
    md += `Please review and fix the following security issues:\n\n`

    results.findings.forEach((finding, index) => {
      md += `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}\n\n`
      md += `**Category:** ${finding.category}\n\n`
      md += `**Description:** ${finding.description}\n\n`
      if (finding.file) {
        md += `**Location:** \`${finding.file}${finding.line ? `:${finding.line}` : ''}\`\n\n`
      }
      md += `---\n\n`
    })

    return md
  }

  const downloadReport = () => {
    const md = generateReport()
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-report-${new Date().toISOString().split('T')[0]}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleStartScan = async () => {
    if (!repoUrl) {
      setError('Please enter a GitHub URL')
      return
    }

    // Validate GitHub URL
    if (!repoUrl.includes('github.com')) {
      setError('Please enter a valid GitHub URL')
      return
    }

    setError('')
    setScanStatus('scanning')
    setStep('scan')

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repoUrl,
          githubToken: githubToken || undefined,
          apiKeys: Object.fromEntries(
            Object.entries(apiKeys).filter(([, v]) => v)
          ),
        }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Scan failed')
      }

      const data = await response.json()

      setResults(data)
      setScanStatus('complete')
      setStep('results')
    } catch (err: unknown) {
      setScanStatus('error')
      setError(err instanceof Error ? err.message : 'Failed to scan repository. Please try again.')
      setStep('setup')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500 text-white'
      case 'high': return 'bg-orange-500 text-white'
      case 'medium': return 'bg-yellow-500 text-black'
      case 'low': return 'bg-green-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-500'
    if (score >= 60) return 'text-yellow-500'
    if (score >= 40) return 'text-orange-500'
    return 'text-red-500'
  }

  return (
    <main className="min-h-screen p-4 md:p-8">
      {/* Header */}
      <nav className="max-w-6xl mx-auto flex items-center justify-between mb-12">
        <div className="flex items-center gap-2">
          <Shield className="w-8 h-8 text-primary-600" />
          <span className="text-xl font-bold gradient-text">Vibe Check</span>
        </div>
        <div className="text-sm text-gray-500">
          Security Scanner for Vibe Coders
        </div>
      </nav>

      <div className="max-w-4xl mx-auto">
        {/* Welcome Step */}
        {step === 'welcome' && (
          <div className="text-center space-y-8">
            {/* Intro Message */}
            <div className="bg-gradient-to-r from-purple-50 to-primary-50 rounded-2xl p-6 md:p-8 border border-purple-200 max-w-4xl mx-auto">
              <div className="flex items-center justify-center gap-2 mb-4">
                <Sparkles className="w-5 h-5 text-purple-500" />
                <span className="text-sm font-medium text-purple-600 uppercase tracking-wide">For Vibe Coders</span>
                <Sparkles className="w-5 h-5 text-purple-500" />
              </div>
              <div className="flex flex-col md:flex-row items-center gap-6">
                <img
                  src="https://upload.wikimedia.org/wikipedia/en/c/c2/Peter_Griffin.png"
                  alt="Peter Griffin"
                  className="w-32 md:w-40 flex-shrink-0"
                />
                <div className="text-left">
                  <p className="text-gray-700 leading-relaxed">
                    You know what grinds my gears? Those "10 years experience" developers acting like you need a
                    computer science degree to build apps. Meanwhile, I'm over here telling AI to <em>"make it work"</em> and
                    it just... works. No rules, no gatekeepers, just vibes and shipping.
                  </p>
                  <p className="text-gray-700 leading-relaxed mt-3">
                    But here's the thing — we don't know what we don't know. Your code runs fine until some hacker
                    finds that API key you accidentally left in there. That's why we built this. <strong>Vibe Check</strong> catches
                    the stuff you never learned to look for. Keep vibing, keep shipping — we'll watch your back.
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <h1 className="text-4xl md:text-5xl font-bold text-gray-800">
                Is Your Code <span className="gradient-text">Secure?</span>
              </h1>
              <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                Scan your GitHub repo for security issues. Find exposed secrets, vulnerable dependencies,
                and unsafe code patterns before hackers do.
              </p>
            </div>

            {/* Features */}
            <div className="glass rounded-2xl p-6 text-left border-2 border-primary-200 max-w-lg mx-auto">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 bg-primary-100 rounded-xl flex items-center justify-center">
                  <Shield className="w-6 h-6 text-primary-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-800">Security Scan</h3>
                  <p className="text-sm text-gray-500">Powered by pattern matching</p>
                </div>
              </div>
              <ul className="space-y-2 text-gray-600 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  Find exposed secrets & API keys
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  Detect vulnerable dependencies
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  Identify unsafe code patterns
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  Download report for your AI coding assistant
                </li>
              </ul>
            </div>

            <button
              onClick={() => setStep('setup')}
              className="bg-primary-600 hover:bg-primary-700 text-white px-8 py-4 rounded-xl font-semibold text-lg flex items-center gap-2 mx-auto transition-all hover:scale-105"
            >
              Get Started <ArrowRight className="w-5 h-5" />
            </button>

            {/* Privacy Notice */}
            <div className="flex items-center justify-center gap-2 text-sm text-gray-500 mt-6">
              <Lock className="w-4 h-4" />
              <span>No backend database. Your code stays on GitHub. Tokens stay in your browser.</span>
            </div>
          </div>
        )}

        {/* Setup Step */}
        {step === 'setup' && (
          <div className="space-y-8">
            <div className="text-center space-y-2">
              <h2 className="text-3xl font-bold text-gray-800">Scan Your Repository</h2>
              <p className="text-gray-600">Enter your GitHub URL to check for security issues</p>
            </div>

            {/* GitHub URL */}
            <div className="glass rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center font-bold">
                  1
                </div>
                <h3 className="text-xl font-semibold text-gray-800">Paste Your GitHub Link</h3>
              </div>

              <div className="relative">
                <Github className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="url"
                  placeholder="https://github.com/username/repository"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="w-full pl-12 pr-4 py-4 rounded-xl border-2 border-gray-200 focus:border-primary-500 focus:outline-none text-lg"
                />
              </div>

              <p className="text-sm text-gray-500">
                Works with public repositories. Add a GitHub token below for private repos.
              </p>

              {/* GitHub Token for Private Repos */}
              <div className="bg-gray-50 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-700 flex items-center gap-2">
                    <Lock className="w-4 h-4" />
                    Private Repo Access (Optional)
                  </span>
                  <a
                    href="https://github.com/settings/tokens/new?scopes=repo&description=Vibe%20Check%20Scanner"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary-600 hover:text-primary-700 flex items-center gap-1"
                  >
                    Get token <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <input
                  type="password"
                  placeholder="ghp_xxxxxxxxxxxx"
                  value={githubToken}
                  onChange={(e) => handleGithubTokenChange(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg border border-gray-200 focus:border-primary-500 focus:outline-none text-sm"
                />
                {githubToken && (
                  <p className="text-xs text-green-600 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    Token saved - you can scan private repos
                  </p>
                )}
              </div>
            </div>

            {/* AI API Keys Section - Required */}
            <div className="glass rounded-2xl p-6 space-y-4 border-2 border-purple-300">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-purple-600 text-white rounded-full flex items-center justify-center font-bold">
                  2
                </div>
                <h3 className="text-xl font-semibold text-gray-800">Add AI Models</h3>
                <span className="bg-purple-100 text-purple-700 text-xs px-2 py-1 rounded-full font-medium">Required</span>
              </div>

              <p className="text-sm text-gray-600">
                Add at least one AI model to scan your code. <strong>The more models you add, the better the security analysis</strong> — each AI catches different vulnerabilities.
              </p>

              {Object.values(apiKeys).filter(k => k).length > 0 && (
                <div className="bg-green-50 border border-green-200 rounded-lg p-3 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                  <span className="text-green-700 font-medium">
                    {Object.values(apiKeys).filter(k => k).length} AI model{Object.values(apiKeys).filter(k => k).length > 1 ? 's' : ''} configured
                  </span>
                </div>
              )}

              <div className="space-y-3">
                {llmProviders.map((provider) => (
                  <div key={provider.id} className={`rounded-lg p-3 space-y-2 ${apiKeys[provider.id] ? 'bg-green-50 border border-green-200' : 'bg-gray-50'}`}>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-700 flex items-center gap-2">
                        <Key className="w-4 h-4" />
                        {provider.name}
                        {apiKeys[provider.id] && <CheckCircle className="w-4 h-4 text-green-600" />}
                      </span>
                      <a
                        href={provider.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-primary-600 hover:text-primary-700 flex items-center gap-1"
                      >
                        Get API key <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                    <input
                      type="password"
                      placeholder={provider.placeholder}
                      value={apiKeys[provider.id]}
                      onChange={(e) => handleApiKeyChange(provider.id, e.target.value)}
                      className="w-full px-3 py-2 rounded-lg border border-gray-200 focus:border-primary-500 focus:outline-none text-sm"
                    />
                  </div>
                ))}
                <p className="text-xs text-gray-500 pt-2">
                  Keys are stored in your browser only. We never save them to any server.
                </p>
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-600 flex items-start gap-2">
                <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                {error}
              </div>
            )}

            {Object.values(apiKeys).filter(k => k).length === 0 && (
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-amber-700 flex items-start gap-2">
                <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <span>Add at least one AI model API key above to start scanning</span>
              </div>
            )}

            <div className="flex gap-4 justify-center">
              <button
                onClick={() => setStep('welcome')}
                className="px-6 py-3 rounded-xl border-2 border-gray-300 text-gray-600 hover:bg-gray-50 transition-all"
              >
                Back
              </button>
              <button
                onClick={handleStartScan}
                disabled={!repoUrl || Object.values(apiKeys).filter(k => k).length === 0}
                className="bg-primary-600 hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white px-8 py-3 rounded-xl font-semibold flex items-center gap-2 transition-all hover:scale-105 disabled:hover:scale-100"
              >
                <Shield className="w-5 h-5" />
                Start AI Security Scan
              </button>
            </div>
          </div>
        )}

        {/* Scanning Step */}
        {step === 'scan' && scanStatus === 'scanning' && (
          <div className="text-center space-y-8 py-12">
            <div className="w-24 h-24 mx-auto bg-primary-100 rounded-full flex items-center justify-center animate-pulse-slow">
              <Loader2 className="w-12 h-12 text-primary-600 animate-spin" />
            </div>
            <div className="space-y-2">
              <h2 className="text-2xl font-bold text-gray-800">Scanning Your Repository...</h2>
              <p className="text-gray-600">This usually takes 10-30 seconds</p>
            </div>

            <div className="glass rounded-2xl p-6 max-w-md mx-auto">
              <div className="space-y-4 text-left">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="text-gray-700">Fetching repository...</span>
                </div>
                <div className="flex items-center gap-3">
                  <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />
                  <span className="text-gray-700">Running pattern analysis...</span>
                </div>
                <div className="flex items-center gap-3">
                  <Loader2 className="w-5 h-5 text-purple-500 animate-spin" />
                  <span className="text-gray-700">AI models analyzing code...</span>
                </div>
                <div className="flex items-center gap-3 opacity-50">
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
                  <span className="text-gray-500">Generating report...</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Results Step */}
        {step === 'results' && results && (
          <div className="space-y-8">
            {/* Score Header */}
            <div className="glass rounded-2xl p-8 text-center">
              <h2 className="text-xl text-gray-600 mb-2">Your Security Score</h2>
              <div className={`text-7xl font-bold ${getScoreColor(results.score)}`}>
                {results.score}
                <span className="text-3xl text-gray-400">/100</span>
              </div>
              <p className="text-gray-600 mt-4">
                {results.score >= 80 ? 'Great job! Your code looks secure.' :
                 results.score >= 60 ? 'Not bad, but there are some issues to fix.' :
                 results.score >= 40 ? 'Your code has several security concerns.' :
                 'Your code needs immediate security attention.'}
              </p>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-red-50 rounded-xl p-4 text-center">
                <div className="text-3xl font-bold text-red-500">{results.summary.critical}</div>
                <div className="text-sm text-red-700">Critical</div>
              </div>
              <div className="bg-orange-50 rounded-xl p-4 text-center">
                <div className="text-3xl font-bold text-orange-500">{results.summary.high}</div>
                <div className="text-sm text-orange-700">High</div>
              </div>
              <div className="bg-yellow-50 rounded-xl p-4 text-center">
                <div className="text-3xl font-bold text-yellow-600">{results.summary.medium}</div>
                <div className="text-sm text-yellow-700">Medium</div>
              </div>
              <div className="bg-green-50 rounded-xl p-4 text-center">
                <div className="text-3xl font-bold text-green-500">{results.summary.low}</div>
                <div className="text-sm text-green-700">Low</div>
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-gray-800">Issues Found</h3>

              {results.findings.length === 0 ? (
                <div className="glass rounded-xl p-6 text-center text-gray-500">
                  No security issues found! Your code looks clean.
                </div>
              ) : (
                results.findings.map((finding) => (
                  <div key={finding.id} className="glass rounded-xl p-6 space-y-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(finding.severity)}`}>
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="text-sm text-gray-500">{finding.category}</span>
                      </div>
                    </div>

                    <h4 className="text-lg font-semibold text-gray-800">{finding.title}</h4>
                    <p className="text-gray-600">{finding.description}</p>

                    {finding.file && (
                      <div className="bg-gray-100 rounded-lg px-4 py-2 text-sm font-mono text-gray-700">
                        {finding.file}{finding.line && `:${finding.line}`}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-4 items-center pt-4">
              <div className="flex gap-4">
                <button
                  onClick={() => {
                    setStep('setup')
                    setResults(null)
                    setScanStatus('idle')
                    setRepoUrl('')
                  }}
                  className="px-6 py-3 rounded-xl border-2 border-gray-300 text-gray-600 hover:bg-gray-50 transition-all"
                >
                  Scan Another Repo
                </button>
                <button
                  onClick={downloadReport}
                  className="bg-primary-600 hover:bg-primary-700 text-white px-8 py-3 rounded-xl font-semibold transition-all flex items-center gap-2"
                >
                  <Download className="w-5 h-5" />
                  Download Report
                </button>
              </div>
              <p className="text-sm text-gray-500">
                Download the .md report and paste it into your AI coding assistant to fix issues
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="max-w-6xl mx-auto mt-16 pt-8 border-t border-gray-200 text-center text-gray-500 text-sm">
        <p>Built by vibe coders, for vibe coders</p>
        <p className="mt-1">Your code and tokens are never stored. We scan and forget.</p>
      </footer>
    </main>
  )
}
