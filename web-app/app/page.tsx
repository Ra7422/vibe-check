'use client'

import { useState } from 'react'
import { Shield, Github, AlertTriangle, CheckCircle, Lock, Eye, Loader2, ArrowRight, Key, Download, FileText, Globe, MousePointer, Sparkles, Zap, ExternalLink } from 'lucide-react'

type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error'
type FlowStatus = 'idle' | 'analyzing' | 'complete' | 'error'

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

interface FlowIssue {
  id: string
  type: 'bug' | 'ux' | 'suggestion'
  element: string
  description: string
  recommendation: string
  source: 'openai' | 'anthropic' | 'google'
}

interface FlowResult {
  issues: FlowIssue[]
  summary: {
    bugs: number
    uxIssues: number
    suggestions: number
  }
  llmResponses: {
    openai?: string
    anthropic?: string
    google?: string
  }
}

export default function Home() {
  const [step, setStep] = useState<'welcome' | 'setup' | 'scan' | 'results' | 'flow-setup' | 'flow-scan' | 'flow-results' | 'final'>('welcome')
  const [repoUrl, setRepoUrl] = useState('')
  const [apiKeys, setApiKeys] = useState({
    openai: '',
    anthropic: '',
    google: '',
  })
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [results, setResults] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')

  // Flow check state
  const [deployedUrl, setDeployedUrl] = useState('')
  const [appDescription, setAppDescription] = useState('')
  const [flowStatus, setFlowStatus] = useState<FlowStatus>('idle')
  const [flowResults, setFlowResults] = useState<FlowResult | null>(null)
  const [currentLlm, setCurrentLlm] = useState<string>('')

  // Check which LLMs are configured
  const configuredLlms = {
    openai: !!apiKeys.openai,
    anthropic: !!apiKeys.anthropic,
    google: !!apiKeys.google,
  }
  const hasAnyLlm = configuredLlms.openai || configuredLlms.anthropic || configuredLlms.google

  // Generate markdown report for LLM (security only)
  const generateSecurityReport = () => {
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

  // Generate combined report (security + flow)
  const generateCombinedReport = () => {
    let md = `# Complete Vibe Check Report\n\n`
    md += `**Date:** ${new Date().toISOString().split('T')[0]}\n\n`

    // Part 1: Security
    md += `---\n\n`
    md += `# Part 1: Security Check\n\n`
    md += `**Repository:** ${repoUrl}\n`
    if (results) {
      md += `**Score:** ${results.score}/100\n\n`
      md += `## Security Summary\n\n`
      md += `| Severity | Count |\n`
      md += `|----------|-------|\n`
      md += `| Critical | ${results.summary.critical} |\n`
      md += `| High | ${results.summary.high} |\n`
      md += `| Medium | ${results.summary.medium} |\n`
      md += `| Low | ${results.summary.low} |\n\n`

      md += `## Security Issues\n\n`
      results.findings.forEach((finding, index) => {
        md += `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}\n\n`
        md += `**Category:** ${finding.category}\n\n`
        md += `**Description:** ${finding.description}\n\n`
        if (finding.file) {
          md += `**Location:** \`${finding.file}${finding.line ? `:${finding.line}` : ''}\`\n\n`
        }
      })
    }

    // Part 2: Flow Check
    md += `---\n\n`
    md += `# Part 2: Flow Check (UX Analysis)\n\n`
    md += `**Deployed URL:** ${deployedUrl}\n`
    md += `**App Description:** ${appDescription}\n\n`

    if (flowResults) {
      md += `## Flow Summary\n\n`
      md += `| Type | Count |\n`
      md += `|------|-------|\n`
      md += `| Bugs | ${flowResults.summary.bugs} |\n`
      md += `| UX Issues | ${flowResults.summary.uxIssues} |\n`
      md += `| Suggestions | ${flowResults.summary.suggestions} |\n\n`

      md += `## Flow Issues\n\n`
      flowResults.issues.forEach((issue, index) => {
        const typeEmoji = issue.type === 'bug' ? '🐛' : issue.type === 'ux' ? '🎨' : '💡'
        md += `### ${index + 1}. ${typeEmoji} ${issue.element}\n\n`
        md += `**Type:** ${issue.type.toUpperCase()}\n`
        md += `**Source:** ${issue.source}\n\n`
        md += `**Issue:** ${issue.description}\n\n`
        md += `**Recommendation:** ${issue.recommendation}\n\n`
      })

      // Raw LLM responses
      md += `## Raw LLM Analysis\n\n`
      if (flowResults.llmResponses.openai) {
        md += `### OpenAI Analysis\n\n${flowResults.llmResponses.openai}\n\n`
      }
      if (flowResults.llmResponses.anthropic) {
        md += `### Anthropic Analysis\n\n${flowResults.llmResponses.anthropic}\n\n`
      }
      if (flowResults.llmResponses.google) {
        md += `### Google AI Analysis\n\n${flowResults.llmResponses.google}\n\n`
      }
    }

    // Instructions for AI
    md += `---\n\n`
    md += `## Instructions for AI Assistant\n\n`
    md += `Please help me fix all the issues listed above. Prioritize:\n`
    md += `1. CRITICAL security issues first\n`
    md += `2. HIGH security issues\n`
    md += `3. Bug fixes from flow analysis\n`
    md += `4. UX improvements\n`
    md += `5. Suggestions for enhancement\n\n`
    md += `For each fix:\n`
    md += `1. Explain what the issue is\n`
    md += `2. Show me the code fix\n`
    md += `3. Explain why the fix works\n`

    return md
  }

  const downloadReport = (type: 'security' | 'combined') => {
    const md = type === 'security' ? generateSecurityReport() : generateCombinedReport()
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${type}-report-${new Date().toISOString().split('T')[0]}.md`
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
    if (!repoUrl.includes('github.com') && !repoUrl.includes('gitlab.com')) {
      setError('Please enter a valid GitHub or GitLab URL')
      return
    }

    setError('')
    setScanStatus('scanning')
    setStep('scan')

    // Call the scan API
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repoUrl,
          apiKeys: apiKeys.openai || apiKeys.anthropic || apiKeys.google ? apiKeys : undefined,
        }),
      })

      if (!response.ok) {
        throw new Error('Scan failed')
      }

      const data = await response.json()

      setResults(data)
      setScanStatus('complete')
      setStep('results')
    } catch (err) {
      setScanStatus('error')
      setError('Failed to scan repository. Please try again.')
      setStep('setup')
    }
  }

  const handleStartFlowCheck = async () => {
    if (!deployedUrl) {
      setError('Please enter your deployed app URL')
      return
    }

    if (!appDescription) {
      setError('Please describe your app so the AI knows what to look for')
      return
    }

    setError('')
    setFlowStatus('analyzing')
    setStep('flow-scan')

    try {
      // Call each configured LLM
      const llmResponses: FlowResult['llmResponses'] = {}
      const allIssues: FlowIssue[] = []

      // OpenAI
      if (apiKeys.openai) {
        setCurrentLlm('OpenAI GPT-4')
        try {
          const response = await fetch('/api/flow-check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: deployedUrl,
              description: appDescription,
              provider: 'openai',
              apiKey: apiKeys.openai,
            }),
          })
          if (response.ok) {
            const data = await response.json()
            llmResponses.openai = data.analysis
            allIssues.push(...data.issues.map((i: FlowIssue) => ({ ...i, source: 'openai' as const })))
          }
        } catch (e) {
          console.error('OpenAI flow check failed:', e)
        }
      }

      // Anthropic
      if (apiKeys.anthropic) {
        setCurrentLlm('Claude')
        try {
          const response = await fetch('/api/flow-check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: deployedUrl,
              description: appDescription,
              provider: 'anthropic',
              apiKey: apiKeys.anthropic,
            }),
          })
          if (response.ok) {
            const data = await response.json()
            llmResponses.anthropic = data.analysis
            allIssues.push(...data.issues.map((i: FlowIssue) => ({ ...i, source: 'anthropic' as const })))
          }
        } catch (e) {
          console.error('Anthropic flow check failed:', e)
        }
      }

      // Google
      if (apiKeys.google) {
        setCurrentLlm('Gemini')
        try {
          const response = await fetch('/api/flow-check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: deployedUrl,
              description: appDescription,
              provider: 'google',
              apiKey: apiKeys.google,
            }),
          })
          if (response.ok) {
            const data = await response.json()
            llmResponses.google = data.analysis
            allIssues.push(...data.issues.map((i: FlowIssue) => ({ ...i, source: 'google' as const })))
          }
        } catch (e) {
          console.error('Google flow check failed:', e)
        }
      }

      // Compile results
      const flowResult: FlowResult = {
        issues: allIssues,
        summary: {
          bugs: allIssues.filter(i => i.type === 'bug').length,
          uxIssues: allIssues.filter(i => i.type === 'ux').length,
          suggestions: allIssues.filter(i => i.type === 'suggestion').length,
        },
        llmResponses,
      }

      setFlowResults(flowResult)
      setFlowStatus('complete')
      setStep('flow-results')
    } catch (err) {
      setFlowStatus('error')
      setError('Flow check failed. Please try again.')
      setStep('flow-setup')
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

  const getIssueTypeColor = (type: string) => {
    switch (type) {
      case 'bug': return 'bg-red-100 text-red-700'
      case 'ux': return 'bg-purple-100 text-purple-700'
      case 'suggestion': return 'bg-blue-100 text-blue-700'
      default: return 'bg-gray-100 text-gray-700'
    }
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
          Security + Flow Scanner for Vibe Coders
        </div>
      </nav>

      {/* Progress Indicator */}
      {step !== 'welcome' && (
        <div className="max-w-4xl mx-auto mb-8">
          <div className="flex items-center justify-center gap-2">
            <div className={`flex items-center gap-2 px-4 py-2 rounded-full ${
              ['setup', 'scan', 'results'].includes(step) || step.startsWith('flow')
                ? 'bg-primary-100 text-primary-700'
                : 'bg-gray-100 text-gray-500'
            }`}>
              <Shield className="w-4 h-4" />
              <span className="text-sm font-medium">Security</span>
              {(step === 'results' || step.startsWith('flow')) && <CheckCircle className="w-4 h-4 text-green-500" />}
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400" />
            <div className={`flex items-center gap-2 px-4 py-2 rounded-full ${
              step.startsWith('flow')
                ? 'bg-purple-100 text-purple-700'
                : 'bg-gray-100 text-gray-500'
            }`}>
              <MousePointer className="w-4 h-4" />
              <span className="text-sm font-medium">Flow Check</span>
              {step === 'flow-results' && <CheckCircle className="w-4 h-4 text-green-500" />}
            </div>
          </div>
        </div>
      )}

      <div className="max-w-4xl mx-auto">
        {/* Welcome Step */}
        {step === 'welcome' && (
          <div className="text-center space-y-8">
            <div className="space-y-4">
              <h1 className="text-4xl md:text-5xl font-bold text-gray-800">
                Is Your Vibe <span className="gradient-text">Right?</span>
              </h1>
              <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                We'll check your code for security issues, then test your deployed app's flows.
                All powered by AI. No coding knowledge required.
              </p>
            </div>

            {/* Features */}
            <div className="grid md:grid-cols-2 gap-6 my-12">
              <div className="glass rounded-2xl p-6 text-left border-2 border-primary-200">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 bg-primary-100 rounded-xl flex items-center justify-center">
                    <Shield className="w-6 h-6 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-800">Step 1: Security Check</h3>
                    <p className="text-sm text-gray-500">Scan your code</p>
                  </div>
                </div>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Find exposed secrets & passwords
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Detect vulnerable dependencies
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Identify unsafe code patterns
                  </li>
                </ul>
              </div>

              <div className="glass rounded-2xl p-6 text-left border-2 border-purple-200">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center">
                    <MousePointer className="w-6 h-6 text-purple-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-800">Step 2: Flow Check</h3>
                    <p className="text-sm text-gray-500">Test your live app</p>
                  </div>
                </div>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    AI tests every button & link
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Find broken flows & dead ends
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Get UX improvement suggestions
                  </li>
                </ul>
              </div>
            </div>

            <button
              onClick={() => setStep('setup')}
              className="bg-primary-600 hover:bg-primary-700 text-white px-8 py-4 rounded-xl font-semibold text-lg flex items-center gap-2 mx-auto transition-all hover:scale-105"
            >
              Get Started <ArrowRight className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Setup Step */}
        {step === 'setup' && (
          <div className="space-y-8">
            <div className="text-center space-y-2">
              <h2 className="text-3xl font-bold text-gray-800">Let's Check Your Code</h2>
              <p className="text-gray-600">First, we'll scan for security issues</p>
            </div>

            {/* Step 1: GitHub URL */}
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
                We support public GitHub and GitLab repositories
              </p>
            </div>

            {/* Step 2: API Keys */}
            <div className="glass rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center font-bold">
                  2
                </div>
                <h3 className="text-xl font-semibold text-gray-800">Your AI Keys</h3>
                <span className="text-sm text-gray-500">(For deeper analysis)</span>
              </div>

              {/* Important Disclaimer */}
              <div className="bg-purple-50 border border-purple-200 rounded-xl p-4 text-sm text-purple-800">
                <div className="flex items-start gap-2">
                  <Lock className="w-5 h-5 mt-0.5 flex-shrink-0" />
                  <div>
                    <strong>Your keys, your testing.</strong> These API keys are used only for YOUR scan session.
                    We never store, log, or access your keys. Built by vibe coders, for vibe coders.
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="password"
                    placeholder="OpenAI API Key"
                    value={apiKeys.openai}
                    onChange={(e) => setApiKeys({...apiKeys, openai: e.target.value})}
                    className="w-full pl-12 pr-12 py-3 rounded-xl border-2 border-gray-200 focus:border-primary-500 focus:outline-none"
                  />
                  <a
                    href="https://platform.openai.com/api-keys"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-primary-600 transition-colors"
                    title="Get OpenAI API Key"
                  >
                    <ExternalLink className="w-5 h-5" />
                  </a>
                </div>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="password"
                    placeholder="Anthropic API Key"
                    value={apiKeys.anthropic}
                    onChange={(e) => setApiKeys({...apiKeys, anthropic: e.target.value})}
                    className="w-full pl-12 pr-12 py-3 rounded-xl border-2 border-gray-200 focus:border-primary-500 focus:outline-none"
                  />
                  <a
                    href="https://console.anthropic.com/settings/keys"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-primary-600 transition-colors"
                    title="Get Anthropic API Key"
                  >
                    <ExternalLink className="w-5 h-5" />
                  </a>
                </div>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="password"
                    placeholder="Google AI API Key"
                    value={apiKeys.google}
                    onChange={(e) => setApiKeys({...apiKeys, google: e.target.value})}
                    className="w-full pl-12 pr-12 py-3 rounded-xl border-2 border-gray-200 focus:border-primary-500 focus:outline-none"
                  />
                  <a
                    href="https://aistudio.google.com/app/apikey"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-primary-600 transition-colors"
                    title="Get Google AI API Key"
                  >
                    <ExternalLink className="w-5 h-5" />
                  </a>
                </div>
              </div>

              <div className="bg-blue-50 rounded-xl p-4 text-sm text-blue-700">
                <strong>Why add API keys?</strong> Each AI will analyze your app from a different perspective.
                More AIs = more comprehensive analysis. You'll need at least one key for Flow Check.
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-600">
                {error}
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
                className="bg-primary-600 hover:bg-primary-700 text-white px-8 py-3 rounded-xl font-semibold flex items-center gap-2 transition-all hover:scale-105"
              >
                <Shield className="w-5 h-5" />
                Start Security Check
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
              <p className="text-gray-600">This usually takes 1-3 minutes</p>
            </div>

            <div className="glass rounded-2xl p-6 max-w-md mx-auto">
              <div className="space-y-4 text-left">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="text-gray-700">Cloning repository...</span>
                </div>
                <div className="flex items-center gap-3">
                  <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />
                  <span className="text-gray-700">Analyzing code patterns...</span>
                </div>
                <div className="flex items-center gap-3 opacity-50">
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
                  <span className="text-gray-500">Checking for vulnerabilities...</span>
                </div>
                <div className="flex items-center gap-3 opacity-50">
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
                  <span className="text-gray-500">Generating report...</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Security Results Step */}
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
                  No security issues found! 🎉
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
                  onClick={() => downloadReport('security')}
                  className="px-6 py-3 rounded-xl border-2 border-gray-300 text-gray-600 hover:bg-gray-50 transition-all flex items-center gap-2"
                >
                  <Download className="w-5 h-5" />
                  Download Security Report
                </button>
                {hasAnyLlm ? (
                  <button
                    onClick={() => setStep('flow-setup')}
                    className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-3 rounded-xl font-semibold transition-all flex items-center gap-2 hover:scale-105"
                  >
                    <MousePointer className="w-5 h-5" />
                    Continue to Flow Check
                    <ArrowRight className="w-5 h-5" />
                  </button>
                ) : (
                  <button
                    onClick={() => setStep('setup')}
                    className="bg-gray-400 text-white px-8 py-3 rounded-xl font-semibold flex items-center gap-2"
                    title="Add API keys to enable Flow Check"
                  >
                    <MousePointer className="w-5 h-5" />
                    Add API Keys for Flow Check
                  </button>
                )}
              </div>
              <p className="text-sm text-gray-500">
                {hasAnyLlm
                  ? "Now let's test your live app's user flows"
                  : "Flow Check requires at least one API key"}
              </p>
            </div>
          </div>
        )}

        {/* Flow Setup Step */}
        {step === 'flow-setup' && (
          <div className="space-y-8">
            <div className="text-center space-y-2">
              <h2 className="text-3xl font-bold text-gray-800">Now Let's Check Your Flows</h2>
              <p className="text-gray-600">Tell us about your app and we'll test every button and link</p>
            </div>

            {/* Deployed URL */}
            <div className="glass rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-purple-600 text-white rounded-full flex items-center justify-center font-bold">
                  1
                </div>
                <h3 className="text-xl font-semibold text-gray-800">Your Deployed App URL</h3>
              </div>

              <div className="relative">
                <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="url"
                  placeholder="https://your-app.vercel.app"
                  value={deployedUrl}
                  onChange={(e) => setDeployedUrl(e.target.value)}
                  className="w-full pl-12 pr-4 py-4 rounded-xl border-2 border-gray-200 focus:border-purple-500 focus:outline-none text-lg"
                />
              </div>

              <p className="text-sm text-gray-500">
                Enter the URL where your app is deployed (Vercel, Netlify, Railway, etc.)
              </p>
            </div>

            {/* App Description */}
            <div className="glass rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-purple-600 text-white rounded-full flex items-center justify-center font-bold">
                  2
                </div>
                <h3 className="text-xl font-semibold text-gray-800">Describe Your App</h3>
              </div>

              <textarea
                placeholder="Example: This is a task management app. Users can sign up, create projects, add tasks with due dates, and mark them complete. There's a dashboard showing task statistics and a settings page for user preferences."
                value={appDescription}
                onChange={(e) => setAppDescription(e.target.value)}
                rows={5}
                className="w-full px-4 py-4 rounded-xl border-2 border-gray-200 focus:border-purple-500 focus:outline-none text-lg resize-none"
              />

              <div className="bg-purple-50 rounded-xl p-4 text-sm text-purple-700">
                <strong>Pro tip:</strong> The more detail you provide, the better the AI can test your app.
                Include: main features, user flows, expected behaviors, and any known issues.
              </div>
            </div>

            {/* LLMs to use */}
            <div className="glass rounded-2xl p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-800">AIs that will analyze your app:</h3>
              <div className="flex flex-wrap gap-3">
                {configuredLlms.openai && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-green-100 text-green-700 rounded-full">
                    <Sparkles className="w-4 h-4" />
                    OpenAI GPT-4
                  </div>
                )}
                {configuredLlms.anthropic && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-orange-100 text-orange-700 rounded-full">
                    <Sparkles className="w-4 h-4" />
                    Claude
                  </div>
                )}
                {configuredLlms.google && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-blue-100 text-blue-700 rounded-full">
                    <Sparkles className="w-4 h-4" />
                    Gemini
                  </div>
                )}
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-600">
                {error}
              </div>
            )}

            <div className="flex gap-4 justify-center">
              <button
                onClick={() => setStep('results')}
                className="px-6 py-3 rounded-xl border-2 border-gray-300 text-gray-600 hover:bg-gray-50 transition-all"
              >
                Back to Security Results
              </button>
              <button
                onClick={handleStartFlowCheck}
                className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-3 rounded-xl font-semibold flex items-center gap-2 transition-all hover:scale-105"
              >
                <Zap className="w-5 h-5" />
                Start Flow Check
              </button>
            </div>
          </div>
        )}

        {/* Flow Scanning Step */}
        {step === 'flow-scan' && flowStatus === 'analyzing' && (
          <div className="text-center space-y-8 py-12">
            <div className="w-24 h-24 mx-auto bg-purple-100 rounded-full flex items-center justify-center animate-pulse-slow">
              <Loader2 className="w-12 h-12 text-purple-600 animate-spin" />
            </div>
            <div className="space-y-2">
              <h2 className="text-2xl font-bold text-gray-800">Analyzing Your App...</h2>
              <p className="text-gray-600">Each AI is testing your buttons and flows</p>
            </div>

            <div className="glass rounded-2xl p-6 max-w-md mx-auto">
              <div className="space-y-4 text-left">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="text-gray-700">Loading your app...</span>
                </div>
                <div className="flex items-center gap-3">
                  <Loader2 className="w-5 h-5 text-purple-500 animate-spin" />
                  <span className="text-gray-700">
                    {currentLlm ? `${currentLlm} is analyzing...` : 'Starting analysis...'}
                  </span>
                </div>
                <div className="flex items-center gap-3 opacity-50">
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
                  <span className="text-gray-500">Testing all buttons & links...</span>
                </div>
                <div className="flex items-center gap-3 opacity-50">
                  <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
                  <span className="text-gray-500">Compiling recommendations...</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Flow Results Step */}
        {step === 'flow-results' && flowResults && (
          <div className="space-y-8">
            {/* Summary Header */}
            <div className="glass rounded-2xl p-8 text-center">
              <h2 className="text-xl text-gray-600 mb-4">Flow Check Complete</h2>
              <div className="flex justify-center gap-8">
                <div>
                  <div className="text-4xl font-bold text-red-500">{flowResults.summary.bugs}</div>
                  <div className="text-sm text-gray-600">Bugs</div>
                </div>
                <div>
                  <div className="text-4xl font-bold text-purple-500">{flowResults.summary.uxIssues}</div>
                  <div className="text-sm text-gray-600">UX Issues</div>
                </div>
                <div>
                  <div className="text-4xl font-bold text-blue-500">{flowResults.summary.suggestions}</div>
                  <div className="text-sm text-gray-600">Suggestions</div>
                </div>
              </div>
            </div>

            {/* Issues List */}
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-gray-800">Issues & Recommendations</h3>

              {flowResults.issues.length === 0 ? (
                <div className="glass rounded-xl p-6 text-center text-gray-500">
                  No issues found! Your app flows look great 🎉
                </div>
              ) : (
                flowResults.issues.map((issue) => (
                  <div key={issue.id} className="glass rounded-xl p-6 space-y-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getIssueTypeColor(issue.type)}`}>
                          {issue.type === 'bug' ? '🐛 Bug' : issue.type === 'ux' ? '🎨 UX' : '💡 Suggestion'}
                        </span>
                        <span className="text-sm text-gray-500">via {issue.source}</span>
                      </div>
                    </div>

                    <h4 className="text-lg font-semibold text-gray-800">{issue.element}</h4>
                    <p className="text-gray-600">{issue.description}</p>

                    <div className="bg-green-50 rounded-lg px-4 py-3 text-sm text-green-800">
                      <strong>Recommendation:</strong> {issue.recommendation}
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Final Actions */}
            <div className="flex flex-col gap-4 items-center pt-4">
              <div className="flex gap-4">
                <button
                  onClick={() => {
                    setStep('setup')
                    setResults(null)
                    setFlowResults(null)
                    setScanStatus('idle')
                    setFlowStatus('idle')
                  }}
                  className="px-6 py-3 rounded-xl border-2 border-gray-300 text-gray-600 hover:bg-gray-50 transition-all"
                >
                  Start Over
                </button>
                <button
                  onClick={() => downloadReport('combined')}
                  className="bg-primary-600 hover:bg-primary-700 text-white px-8 py-3 rounded-xl font-semibold transition-all flex items-center gap-2"
                >
                  <Download className="w-5 h-5" />
                  Download Full Report for LLM
                </button>
              </div>
              <p className="text-sm text-gray-500">
                Get a complete .md file with security + flow issues to paste into your coding AI
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="max-w-6xl mx-auto mt-16 pt-8 border-t border-gray-200 text-center text-gray-500 text-sm">
        <p>Built by vibe coders, for vibe coders</p>
        <p className="mt-1">Your code and API keys are never stored. We scan and forget.</p>
      </footer>
    </main>
  )
}
