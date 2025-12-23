import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  try {
    const { code } = await request.json()

    if (!code) {
      return NextResponse.json(
        { error: 'Missing authorization code' },
        { status: 400 }
      )
    }

    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    })

    const tokenData = await tokenResponse.json()

    if (tokenData.error) {
      return NextResponse.json(
        {
          error: tokenData.error_description || tokenData.error || 'OAuth failed',
          details: tokenData.error,
          hint: 'Check GitHub OAuth App callback URL matches: ' + (process.env.VERCEL_URL || 'codevibe-check.vercel.app')
        },
        { status: 400 }
      )
    }

    // Get user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: 'application/vnd.github.v3+json',
      },
    })

    const userData = await userResponse.json()

    return NextResponse.json({
      access_token: tokenData.access_token,
      login: userData.login,
    })
  } catch (error) {
    return NextResponse.json(
      { error: 'OAuth exchange failed' },
      { status: 500 }
    )
  }
}
