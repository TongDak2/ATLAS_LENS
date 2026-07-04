import type { InvestigationResult } from '../types/atlas'

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json()
    if (typeof body?.detail === 'string') return body.detail
    if (Array.isArray(body?.detail)) return body.detail.map((x: { msg?: string }) => x.msg || JSON.stringify(x)).join(' / ')
  } catch {
    // fall through
  }
  return `Atlas API failed: ${res.status}`
}

export async function investigate(query: string, apiKey: string): Promise<InvestigationResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (apiKey.trim()) headers['X-Atlas-API-Key'] = apiKey.trim()
  const res = await fetch('/api/investigate', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      query,
      time_window_days: 3650,
      classification: 'UNCLASSIFIED//CTI',
      live: true,
      max_results_per_source: 5,
      include_public_feeds: true
    })
  })
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}
