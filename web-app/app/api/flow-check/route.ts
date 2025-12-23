import { NextRequest, NextResponse } from 'next/server'

interface FlowCheckRequest {
  url: string
  description: string
  provider: 'openai' | 'anthropic' | 'google'
  apiKey: string
}

interface FlowIssue {
  id: string
  type: 'bug' | 'ux' | 'suggestion'
  element: string
  description: string
  recommendation: string
}

interface FlowCheckResponse {
  analysis: string
  issues: FlowIssue[]
}

const SYSTEM_PROMPT = `You are a UX and QA expert analyzing a web application. You will receive:
1. The URL of a deployed web application
2. A description of what the app is supposed to do
3. The HTML content of the page

Your job is to:
1. Analyze the page structure and identify all interactive elements (buttons, links, forms, inputs)
2. Check if the UI makes sense for the described purpose
3. Identify potential bugs, UX issues, and areas for improvement

Respond in JSON format with this structure:
{
  "analysis": "A brief overall assessment of the app's UX and functionality",
  "issues": [
    {
      "id": "1",
      "type": "bug|ux|suggestion",
      "element": "The element or area affected (e.g., 'Login button', 'Navigation menu')",
      "description": "What's wrong or could be improved",
      "recommendation": "Specific action to fix or improve"
    }
  ]
}

Types explained:
- bug: Something that appears broken or non-functional
- ux: Poor user experience (confusing layout, unclear labels, accessibility issues)
- suggestion: Enhancement ideas that could make the app better

Be thorough but practical. Focus on issues that would actually impact users.`

async function fetchPageContent(url: string): Promise<string> {
  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VibeCheck/1.0)',
      },
    })

    if (!response.ok) {
      throw new Error(`Failed to fetch page: ${response.status}`)
    }

    const html = await response.text()

    // Extract meaningful content (remove scripts, styles, etc.)
    const cleanedHtml = html
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/\s+/g, ' ')
      .trim()

    // Limit to first 50k chars to stay within token limits
    return cleanedHtml.substring(0, 50000)
  } catch (error) {
    throw new Error(`Could not fetch page content: ${error}`)
  }
}

async function analyzeWithOpenAI(apiKey: string, url: string, description: string, htmlContent: string): Promise<FlowCheckResponse> {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'gpt-4-turbo-preview',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        {
          role: 'user',
          content: `URL: ${url}\n\nApp Description: ${description}\n\nPage HTML:\n${htmlContent}`
        }
      ],
      response_format: { type: 'json_object' },
      max_tokens: 4000,
    }),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`OpenAI API error: ${error}`)
  }

  const data = await response.json()
  const content = data.choices[0].message.content
  return JSON.parse(content)
}

async function analyzeWithAnthropic(apiKey: string, url: string, description: string, htmlContent: string): Promise<FlowCheckResponse> {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-3-sonnet-20240229',
      max_tokens: 4000,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: `URL: ${url}\n\nApp Description: ${description}\n\nPage HTML:\n${htmlContent}\n\nRespond with JSON only.`
        }
      ],
    }),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Anthropic API error: ${error}`)
  }

  const data = await response.json()
  const content = data.content[0].text

  // Extract JSON from response (Claude might include markdown code blocks)
  const jsonMatch = content.match(/\{[\s\S]*\}/)
  if (!jsonMatch) {
    throw new Error('Could not parse Claude response as JSON')
  }

  return JSON.parse(jsonMatch[0])
}

async function analyzeWithGoogle(apiKey: string, url: string, description: string, htmlContent: string): Promise<FlowCheckResponse> {
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      contents: [
        {
          parts: [
            {
              text: `${SYSTEM_PROMPT}\n\nURL: ${url}\n\nApp Description: ${description}\n\nPage HTML:\n${htmlContent}\n\nRespond with JSON only.`
            }
          ]
        }
      ],
      generationConfig: {
        maxOutputTokens: 4000,
      },
    }),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Google AI API error: ${error}`)
  }

  const data = await response.json()
  const content = data.candidates[0].content.parts[0].text

  // Extract JSON from response
  const jsonMatch = content.match(/\{[\s\S]*\}/)
  if (!jsonMatch) {
    throw new Error('Could not parse Gemini response as JSON')
  }

  return JSON.parse(jsonMatch[0])
}

export async function POST(request: NextRequest) {
  try {
    const body: FlowCheckRequest = await request.json()
    const { url, description, provider, apiKey } = body

    // Validate inputs
    if (!url || !description || !provider || !apiKey) {
      return NextResponse.json(
        { error: 'Missing required fields: url, description, provider, apiKey' },
        { status: 400 }
      )
    }

    // Validate URL
    try {
      new URL(url)
    } catch {
      return NextResponse.json(
        { error: 'Invalid URL provided' },
        { status: 400 }
      )
    }

    // Fetch page content
    let htmlContent: string
    try {
      htmlContent = await fetchPageContent(url)
    } catch (error) {
      return NextResponse.json(
        { error: `Could not fetch page: ${error}` },
        { status: 400 }
      )
    }

    // Analyze with the appropriate LLM
    let result: FlowCheckResponse
    try {
      switch (provider) {
        case 'openai':
          result = await analyzeWithOpenAI(apiKey, url, description, htmlContent)
          break
        case 'anthropic':
          result = await analyzeWithAnthropic(apiKey, url, description, htmlContent)
          break
        case 'google':
          result = await analyzeWithGoogle(apiKey, url, description, htmlContent)
          break
        default:
          return NextResponse.json(
            { error: 'Invalid provider. Use openai, anthropic, or google.' },
            { status: 400 }
          )
      }
    } catch (error) {
      console.error(`${provider} analysis error:`, error)
      return NextResponse.json(
        { error: `Analysis failed: ${error}` },
        { status: 500 }
      )
    }

    // Ensure issues have IDs
    result.issues = result.issues.map((issue, index) => ({
      ...issue,
      id: issue.id || String(index + 1),
    }))

    return NextResponse.json(result)

  } catch (error) {
    console.error('Flow check error:', error)
    return NextResponse.json(
      { error: 'Flow check failed. Please try again.' },
      { status: 500 }
    )
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'Vibe Check Flow Analysis API',
    version: '1.0.0',
    usage: 'POST /api/flow-check with { url, description, provider, apiKey }',
    providers: ['openai', 'anthropic', 'google'],
  })
}
