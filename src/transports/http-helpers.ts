import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'HttpRequestError';
    this.status = status;
  }
}

export interface HttpConfig {
  host: string;
  port: number;
  maxBodyBytes: number;
  httpToken?: string;
}

export function getHttpConfig(): HttpConfig {
  return {
    host: process.env.MCP_HTTP_HOST ?? process.env.HOST ?? '127.0.0.1',
    port: Number(process.env.PORT ?? 3000),
    maxBodyBytes: Number(process.env.MCP_MAX_BODY_BYTES ?? 10_485_760),
    httpToken: process.env.MCP_HTTP_TOKEN || undefined,
  };
}

export function assertAuthorized(req: IncomingMessage, config = getHttpConfig()): void {
  if (!config.httpToken) {
    return;
  }

  const header = req.headers.authorization ?? '';
  if (!tokensEqual(header, `Bearer ${config.httpToken}`)) {
    throw new HttpRequestError(401, 'Unauthorized');
  }
}

/** Constant-time string comparison; both sides are hashed so lengths match. */
export function tokensEqual(actual: string, expected: string): boolean {
  const a = createHash('sha256').update(actual, 'utf8').digest();
  const b = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(a, b);
}

/**
 * Trusting a forwarded user header is only safe when every request must also
 * present MCP_HTTP_TOKEN (i.e. only the trusted proxy can reach the server).
 * Throws when any of the given *_TRUST_FORWARDED_USER flags is enabled
 * without a token, so the HTTP transport refuses to start.
 */
export function assertForwardedUserRequiresToken(
  trustFlags: readonly string[],
  config: Pick<HttpConfig, 'httpToken'> = getHttpConfig(),
  env: NodeJS.ProcessEnv = process.env,
): void {
  const enabled = trustFlags.filter(name => env[name] === 'true');
  if (enabled.length && !config.httpToken) {
    throw new Error(
      `${enabled.join(', ')}=true requires MCP_HTTP_TOKEN to be set; refusing to start the HTTP server ` +
        'because forwarded user headers could be spoofed by any client.',
    );
  }
}

/**
 * Caller identity forwarded by the gateway in X-MCP-User, for audit logging
 * only. Control characters are stripped and the value is length-capped.
 */
export function callerIdentity(req: IncomingMessage): string | undefined {
  const raw = req.headers['x-mcp-user'];
  const value = (Array.isArray(raw) ? raw[0] : raw)?.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return value ? value.slice(0, 256) : undefined;
}

export function assertAllowedOrigin(req: IncomingMessage): void {
  if (!isOriginAllowed(req.headers.origin)) {
    throw new HttpRequestError(403, 'Origin not allowed');
  }
}

export async function readJsonBody(
  req: IncomingMessage,
  maxBodyBytes = getHttpConfig().maxBodyBytes,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.byteLength;
    if (totalBytes > maxBodyBytes) {
      throw new HttpRequestError(413, 'Payload too large');
    }
    chunks.push(buffer);
  }

  const text = Buffer.concat(chunks).toString('utf8');
  return text ? (JSON.parse(text) as unknown) : undefined;
}

export function sendJson(
  res: ServerResponse,
  status: number,
  payload: unknown,
  req?: IncomingMessage,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(status, {
    ...corsHeaders(req),
    'Content-Type': 'application/json',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

export function corsHeaders(req?: IncomingMessage): Record<string, string> {
  const origin = req?.headers.origin;
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-session-id',
  };

  if (process.env.MCP_ALLOW_ANY_ORIGIN === 'true') {
    headers['Access-Control-Allow-Origin'] = '*';
    return headers;
  }

  if (origin && isOriginAllowed(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers.Vary = 'Origin';
  }

  return headers;
}

export function isOriginAllowed(origin: string | undefined): boolean {
  if (!origin || process.env.MCP_ALLOW_ANY_ORIGIN === 'true') {
    return true;
  }

  const configuredOrigins = (process.env.MCP_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
  if (configuredOrigins.length) {
    return configuredOrigins.includes(origin);
  }

  try {
    const url = new URL(origin);
    return ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  } catch {
    return false;
  }
}
