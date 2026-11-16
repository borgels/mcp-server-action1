import { createHash, timingSafeEqual } from 'node:crypto';
import { isIPv6 } from 'node:net';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  ConfigError,
  type Env,
  readEnvBoolean,
  readEnvInteger,
  readEnvList,
  readEnvPort,
  readEnvString,
} from '../config-env.js';

export const MIN_TOKEN_LENGTH = 32;

export class HttpRequestError extends Error {
  readonly status: number;
  readonly headers: Record<string, string>;
  /** When set, the response body is a JSON-RPC error with this code. */
  readonly jsonRpcCode?: number;

  constructor(
    status: number,
    message: string,
    options: { headers?: Record<string, string>; jsonRpcCode?: number } = {},
  ) {
    super(message);
    this.name = 'HttpRequestError';
    this.status = status;
    this.headers = options.headers ?? {};
    this.jsonRpcCode = options.jsonRpcCode;
  }
}

export interface HttpConfig {
  host: string;
  port: number;
  maxBodyBytes: number;
  httpToken?: string;
  /** Serve /mcp without a token even when that would otherwise be refused. */
  allowUnauthenticated?: boolean;
  allowAnyOrigin?: boolean;
  /** Exact Origin values allowed; empty means any localhost origin. */
  allowedOrigins?: string[];
  /**
   * Host names (no port) allowed in the Host header on /mcp. Empty means:
   * localhost names and the bind address when bound to loopback, no Host
   * check otherwise.
   */
  allowedHosts?: string[];
  /** Failed auth attempts per remote address before further failures get 429; 0 disables. */
  authFailureLimit?: number;
  authFailureWindowMs?: number;
}

const DEFAULT_MAX_BODY_BYTES = 10_485_760;
export const DEFAULT_AUTH_FAILURE_LIMIT = 20;
export const DEFAULT_AUTH_FAILURE_WINDOW_MS = 60_000;

/**
 * Reads and validates the HTTP transport configuration. Throws ConfigError
 * for invalid values and for insecure combinations (see assertSecureConfig).
 */
export function getHttpConfig(env: Env = process.env): HttpConfig {
  const config: HttpConfig = {
    host: readEnvString('MCP_HTTP_HOST', env) ?? readEnvString('HOST', env) ?? '127.0.0.1',
    port: readEnvPort('PORT', 3000, env),
    maxBodyBytes: readEnvInteger('MCP_MAX_BODY_BYTES', DEFAULT_MAX_BODY_BYTES, {}, env),
    // Not trimmed: the token is compared byte for byte.
    httpToken: env.MCP_HTTP_TOKEN || undefined,
    allowUnauthenticated: readEnvBoolean('MCP_HTTP_ALLOW_UNAUTHENTICATED', false, env),
    allowAnyOrigin: readEnvBoolean('MCP_ALLOW_ANY_ORIGIN', false, env),
    allowedOrigins: readEnvList('MCP_ALLOWED_ORIGINS', env),
    allowedHosts: readEnvList('MCP_ALLOWED_HOSTS', env).map(normalizeAllowedHost),
    authFailureLimit: readEnvInteger('MCP_AUTH_FAILURE_LIMIT', DEFAULT_AUTH_FAILURE_LIMIT, { min: 0 }, env),
    authFailureWindowMs: readEnvInteger('MCP_AUTH_FAILURE_WINDOW_MS', DEFAULT_AUTH_FAILURE_WINDOW_MS, {}, env),
  };
  assertSecureConfig(config);
  return config;
}

/**
 * Refuses configurations that would expose /mcp without authentication:
 * a non-loopback bind address or MCP_ALLOW_ANY_ORIGIN=true without
 * MCP_HTTP_TOKEN, unless MCP_HTTP_ALLOW_UNAUTHENTICATED=true. A configured
 * token must be at least MIN_TOKEN_LENGTH characters.
 */
export function assertSecureConfig(config: HttpConfig): void {
  if (config.httpToken !== undefined && config.httpToken.length < MIN_TOKEN_LENGTH) {
    throw new ConfigError(
      `MCP_HTTP_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters long ` +
        '(for example: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))").',
    );
  }

  if (config.httpToken !== undefined && !/^[\x21-\x7E]+$/.test(config.httpToken)) {
    throw new ConfigError(
      'MCP_HTTP_TOKEN must only contain printable ASCII characters without whitespace; ' +
        'check for a trailing newline or carriage return.',
    );
  }

  if (config.httpToken || config.allowUnauthenticated) {
    return;
  }

  if (!isLoopbackHost(config.host)) {
    throw new ConfigError(
      `Refusing to listen on ${config.host} (from MCP_HTTP_HOST or HOST) without MCP_HTTP_TOKEN: anyone who can reach this address ` +
        'could use the Action1 API identity. Set MCP_HTTP_TOKEN, bind to 127.0.0.1, or set ' +
        'MCP_HTTP_ALLOW_UNAUTHENTICATED=true if access is restricted by other means.',
    );
  }

  if (config.allowAnyOrigin) {
    throw new ConfigError(
      'MCP_ALLOW_ANY_ORIGIN=true requires MCP_HTTP_TOKEN: without it any web page opened on this machine ' +
        'could call the server. Set MCP_HTTP_TOKEN or set MCP_HTTP_ALLOW_UNAUTHENTICATED=true.',
    );
  }
}

/** Warnings to log at startup for configurations that are allowed but risky. */
export function configWarnings(config: HttpConfig): string[] {
  if (config.httpToken || !config.allowUnauthenticated) {
    return [];
  }
  if (!isLoopbackHost(config.host) || config.allowAnyOrigin) {
    return [
      `WARNING: MCP_HTTP_ALLOW_UNAUTHENTICATED=true and no MCP_HTTP_TOKEN: /mcp on ${config.host} accepts ` +
        'unauthenticated requests' +
        (config.allowAnyOrigin ? ' from any web origin' : '') +
        '. Anyone who can reach it can act as the Action1 API identity.',
    ];
  }
  return [];
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
  if (normalized === 'localhost' || normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
    return true;
  }
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized)) {
    return true;
  }
  return /^::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized);
}

export function assertAuthorized(req: IncomingMessage, config: Pick<HttpConfig, 'httpToken'>): void {
  if (!config.httpToken) {
    return;
  }

  // The auth scheme is case-insensitive (RFC 9110); only the token is compared.
  const match = /^Bearer +(\S+) *$/i.exec(req.headers.authorization ?? '');
  if (!tokensEqual(match?.[1] ?? '', config.httpToken)) {
    throw new HttpRequestError(401, 'Unauthorized', { headers: { 'WWW-Authenticate': 'Bearer' } });
  }
}

/** Constant-time string comparison; both sides are hashed so lengths match. */
export function tokensEqual(actual: string, expected: string): boolean {
  const a = createHash('sha256').update(actual, 'utf8').digest();
  const b = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(a, b);
}

/**
 * Caller identity forwarded by an upstream gateway in X-MCP-User, for audit
 * logging only (it grants nothing). Control characters are stripped and the
 * value is length-capped.
 */
export function callerIdentity(req: IncomingMessage): string | undefined {
  const raw = req.headers['x-mcp-user'];
  const value = (Array.isArray(raw) ? raw[0] : raw)?.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return value ? value.slice(0, 256) : undefined;
}

export function assertAllowedOrigin(req: IncomingMessage, config: HttpConfig): void {
  if (!isOriginAllowed(req.headers.origin, config)) {
    throw new HttpRequestError(403, 'Origin not allowed');
  }
}

/**
 * Validates the Host header to guard against DNS rebinding. With
 * MCP_ALLOWED_HOSTS set, the host name (port ignored) must be listed. Without
 * it, a loopback-bound server only accepts localhost names and its own bind
 * address; a server bound elsewhere does not check the Host header.
 */
export function assertAllowedHost(req: IncomingMessage, config: HttpConfig): void {
  let allowed = (config.allowedHosts ?? []).map(formatHostname);
  if (!allowed.length) {
    if (!isLoopbackHost(config.host)) {
      return;
    }
    allowed = ['localhost', '127.0.0.1', '[::1]', formatHostname(config.host)];
  }

  const hostname = hostnameFromHostHeader(req.headers.host);
  if (!hostname || !allowed.includes(hostname)) {
    throw new HttpRequestError(403, 'Host not allowed');
  }
}

const HOSTNAME = String.raw`(\[[0-9a-f:.]+\]|[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?)`;
const HOST_HEADER_PATTERN = new RegExp(String.raw`^${HOSTNAME}(?::\d{1,5})?$`);
const HOSTNAME_PATTERN = new RegExp(`^${HOSTNAME}$`);

/** Lowercases, brackets bare IPv6 literals and drops a trailing dot. */
function formatHostname(host: string): string {
  const lower = host.trim().toLowerCase();
  const bracketed = isIPv6(lower) ? `[${lower}]` : lower;
  return bracketed.endsWith('.') ? bracketed.slice(0, -1) : bracketed;
}

/** Strictly parses `hostname[:port]`; userinfo, paths and queries are rejected. */
function hostnameFromHostHeader(host: string | undefined): string | undefined {
  const match = host ? HOST_HEADER_PATTERN.exec(host.trim().toLowerCase()) : null;
  return match?.[1] ? formatHostname(match[1]) : undefined;
}

/**
 * Validates and normalises one MCP_ALLOWED_HOSTS entry: a bare host name or
 * IP literal without scheme, port or path (the Host header port is ignored).
 */
export function normalizeAllowedHost(entry: string): string {
  const normalized = formatHostname(entry);
  if (!HOSTNAME_PATTERN.test(normalized)) {
    throw new ConfigError(
      `MCP_ALLOWED_HOSTS entries must be host names without scheme, port or path; got ${JSON.stringify(entry)}.`,
    );
  }
  return normalized;
}

export async function readJsonBody(req: IncomingMessage, maxBodyBytes: number): Promise<unknown> {
  const declaredLength = Number(req.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
    throw new HttpRequestError(413, 'Payload too large');
  }

  const chunks: Buffer[] = [];
  let totalBytes = 0;

  try {
    for await (const chunk of req) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buffer.byteLength;
      if (totalBytes > maxBodyBytes) {
        throw new HttpRequestError(413, 'Payload too large');
      }
      chunks.push(buffer);
    }
  } catch (error) {
    if (error instanceof HttpRequestError) {
      throw error;
    }
    throw new HttpRequestError(400, 'Request body could not be read (connection aborted)');
  }

  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpRequestError(400, 'Parse error: request body is not valid JSON', { jsonRpcCode: -32700 });
  }
}

export function sendJson(
  res: ServerResponse,
  status: number,
  payload: unknown,
  req?: IncomingMessage,
  extraHeaders: Record<string, string> = {},
  config?: HttpConfig,
): void {
  res.writeHead(status, {
    ...(req && config ? corsHeaders(req, config) : {}),
    'Content-Type': 'application/json',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

export function corsHeaders(req: IncomingMessage, config: HttpConfig): Record<string, string> {
  const origin = req.headers.origin;
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-session-id, mcp-protocol-version',
    'Access-Control-Expose-Headers': 'mcp-session-id, WWW-Authenticate, Retry-After',
    Vary: 'Origin',
  };

  if (config.allowAnyOrigin) {
    headers['Access-Control-Allow-Origin'] = '*';
    return headers;
  }

  if (origin && isOriginAllowed(origin, config)) {
    headers['Access-Control-Allow-Origin'] = origin;
  }

  return headers;
}

export function isOriginAllowed(
  origin: string | undefined,
  config: Pick<HttpConfig, 'allowAnyOrigin' | 'allowedOrigins'>,
): boolean {
  if (!origin || config.allowAnyOrigin) {
    return true;
  }

  const configuredOrigins = config.allowedOrigins ?? [];
  if (configuredOrigins.length) {
    return configuredOrigins.includes(origin);
  }

  try {
    const url = new URL(origin);
    return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Fixed-window counter of failed authentication attempts per key (remote
 * address). Memory is bounded by `maxEntries`; expired entries are swept and,
 * if still full, the oldest entry is evicted.
 */
export class AuthFailureLimiter {
  private readonly entries = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxEntries = 10_000,
  ) {}

  /** Seconds until the key may retry, or 0 when it is not blocked. */
  retryAfterSeconds(key: string, now = Date.now()): number {
    const entry = this.entries.get(key);
    if (!entry) {
      return 0;
    }
    if (entry.resetAt <= now) {
      this.entries.delete(key);
      return 0;
    }
    return entry.count >= this.limit ? Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) : 0;
  }

  /** Records a failure; returns true when this failure reaches the limit. */
  recordFailure(key: string, now = Date.now()): boolean {
    const entry = this.entries.get(key);
    if (entry && entry.resetAt > now) {
      entry.count += 1;
      return entry.count === this.limit;
    }
    if (entry) {
      this.entries.delete(key);
    }
    if (this.entries.size >= this.maxEntries) {
      this.sweep(now);
      if (this.entries.size >= this.maxEntries) {
        const oldest = this.entries.keys().next().value;
        if (oldest !== undefined) {
          this.entries.delete(oldest);
        }
      }
    }
    this.entries.set(key, { count: 1, resetAt: now + this.windowMs });
    return this.limit === 1;
  }

  get size(): number {
    return this.entries.size;
  }

  private sweep(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.resetAt <= now) {
        this.entries.delete(key);
      }
    }
  }
}
