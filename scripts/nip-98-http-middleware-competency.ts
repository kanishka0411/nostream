#!/usr/bin/env node
// NIP-98 HTTP auth middleware -- competency test for Summer of Bitcoin 2026.
//
// Starts a small HTTP server that accepts any path and verifies the
// `Authorization: Nostr <base64 event>` header against the request.
//
// Run:   npx ts-node scripts/nip-98-http-middleware-competency.ts
// Test:  curl -i -X POST http://127.0.0.1:8009/admin \
//          -H 'Content-Type: application/json' \
//          -H "Authorization: Nostr <base64 event JSON>" \
//          -d '{"hello":"world"}'

import { schnorr } from '@noble/secp256k1'
import { createHash } from 'node:crypto'
import http, { IncomingMessage, ServerResponse } from 'node:http'

const PORT = Number(process.env.PORT ?? 8009)
const NIP98_KIND = 27235
const MAX_CLOCK_SKEW = 60 // seconds -- spec-recommended replay window
const MAX_BODY_BYTES = 1024 * 1024

interface NostrEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: string[][]
  content: string
  sig: string
}

function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex')
}

function findTag(event: NostrEvent, name: string): string | undefined {
  return event.tags.find((t) => t[0] === name)?.[1]
}

function firstValue(header: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(header) ? header[0] : header
  return raw?.split(',')[0]?.trim() || undefined
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > MAX_BODY_BYTES) throw new Error('request body too large')
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

function parseAuthEvent(header: string | undefined): NostrEvent {
  if (!header) throw new Error('missing Authorization header')

  // HTTP auth scheme is case-insensitive (RFC 7235).
  const space = header.indexOf(' ')
  if (space === -1 || header.slice(0, space).toLowerCase() !== 'nostr') {
    throw new Error('expected "Nostr <base64 event>" scheme')
  }

  const encoded = header.slice(space + 1).trim()
  if (!encoded) throw new Error('missing base64 event in Authorization header')

  const json = Buffer.from(encoded, 'base64').toString('utf8')

  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('Authorization event is not valid JSON')
  }

  const e = parsed as Partial<NostrEvent>
  if (
    !e ||
    typeof e.id !== 'string' ||
    typeof e.pubkey !== 'string' ||
    typeof e.created_at !== 'number' ||
    typeof e.kind !== 'number' ||
    !Array.isArray(e.tags) ||
    typeof e.content !== 'string' ||
    typeof e.sig !== 'string'
  ) {
    throw new Error('decoded event is missing required fields')
  }

  return e as NostrEvent
}

function serializeForId(e: NostrEvent): string {
  return JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])
}

async function verifySignedEvent(event: NostrEvent): Promise<boolean> {
  if (sha256Hex(serializeForId(event)) !== event.id) return false
  try {
    return await schnorr.verify(event.sig, event.id, event.pubkey)
  } catch {
    return false
  }
}

async function verifyRequest(req: IncomingMessage, body: Buffer): Promise<string | null> {
  const event = parseAuthEvent(req.headers.authorization)

  if (event.kind !== NIP98_KIND) {
    return `expected kind ${NIP98_KIND}`
  }

  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - event.created_at) > MAX_CLOCK_SKEW) {
    return 'created_at is outside the replay window'
  }

  if (!(await verifySignedEvent(event))) {
    return 'invalid event signature'
  }

  const method = (req.method ?? 'GET').toUpperCase()
  if (findTag(event, 'method')?.toUpperCase() !== method) {
    return 'method tag does not match the request'
  }

  // Only trust forwarded headers from a loopback reverse proxy. The full
  // middleware would use settings.network.trustedProxies (see src/utils/http.ts).
  const remote = req.socket.remoteAddress ?? ''
  const trustForwarded = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1'
  const forwardedHost = trustForwarded ? firstValue(req.headers['x-forwarded-host']) : undefined
  const forwardedProto = trustForwarded ? firstValue(req.headers['x-forwarded-proto']) : undefined
  const host = forwardedHost ?? req.headers.host
  if (!host) return 'missing Host header'
  const proto = forwardedProto ?? ((req.socket as { encrypted?: boolean }).encrypted ? 'https' : 'http')
  const url = new URL(req.url ?? '/', `${proto}://${host}`).toString()
  if (findTag(event, 'u') !== url) {
    return 'u tag does not match the request URL'
  }

  const payload = findTag(event, 'payload')
  if (payload !== undefined) {
    if (payload !== sha256Hex(body)) return 'payload tag does not match body hash'
  } else if (body.length > 0) {
    return 'missing payload tag for request with body'
  }

  return null
}

function json(res: ServerResponse, code: number, body: unknown): void {
  res.statusCode = code
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(body))
}

const server = http.createServer(async (req, res) => {
  try {
    const body = await readBody(req)
    const error = await verifyRequest(req, body)
    if (error) return json(res, 401, { ok: false, error })
    return json(res, 200, { ok: true })
  } catch (err) {
    return json(res, 401, { ok: false, error: (err as Error).message })
  }
})

server.listen(PORT, () => {
  console.log(`NIP-98 middleware listening on http://127.0.0.1:${PORT}`)
})
