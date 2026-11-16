import { type Env, readEnvInteger } from '../config-env.js';
import { Action1HttpError } from '../errors.js';

export interface Action1ClientOptions {
  clientId?: string;
  clientSecret?: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export type QueryValue = string | number | boolean | null | undefined;

/** Region base URLs; the default is Europe. NA: app.action1.com, AU: app.au.action1.com. */
const DEFAULT_BASE_URL = 'https://app.eu.action1.com/api/3.0';

/** Error bodies are read up to this many bytes. */
const MAX_ERROR_BODY_BYTES = 64 * 1024;

/** ACTION1_TIMEOUT_MS, validated (1 ms to 10 minutes); throws ConfigError on invalid values. */
export function action1EnvTimeoutMs(env: Env = process.env): number {
  return readEnvInteger('ACTION1_TIMEOUT_MS', 30_000, { min: 1, max: 600_000 }, env);
}

/** Refresh the token a minute before its fixed 3600 s expiry. */
const TOKEN_SAFETY_MARGIN_MS = 60_000;

/**
 * Client for the Action1 REST API (3.0). OAuth2 client-credentials: tokens
 * are fetched from /oauth2/token, live exactly 3600 s, and are cached and
 * renewed automatically. Action1 recommends staying below ~30 requests/min
 * per enterprise; 429s carry a retry_after and are surfaced as errors.
 */
export class Action1Client {
  private readonly clientId?: string;
  private readonly clientSecret?: string;
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private accessToken?: string;
  private tokenExpiresAt = 0;

  constructor(options: Action1ClientOptions = {}) {
    this.clientId = options.clientId ?? process.env.ACTION1_CLIENT_ID;
    this.clientSecret = options.clientSecret ?? process.env.ACTION1_CLIENT_SECRET;
    this.baseUrl = trimTrailingSlash(options.baseUrl ?? process.env.ACTION1_BASE_URL ?? DEFAULT_BASE_URL);
    assertSafeBaseUrl(this.baseUrl);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? action1EnvTimeoutMs();
  }

  async get<T>(path: string, query?: Record<string, QueryValue>): Promise<T> {
    return this.request<T>('GET', path, query);
  }

  async post<T>(path: string, body?: unknown, query?: Record<string, QueryValue>): Promise<T> {
    return this.request<T>('POST', path, query, body);
  }

  buildUrl(path: string, query?: Record<string, QueryValue>): string {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    const url = new URL(`${this.baseUrl}${normalizedPath}`);
    // Defence in depth: the resolved path must be exactly base path + the
    // requested path. Dot segments or backslashes that the URL parser
    // normalises away would change it and are refused here.
    const basePath = new URL(this.baseUrl).pathname.replace(/\/+$/, '');
    if (url.pathname !== `${basePath}${normalizedPath.split('?')[0]}` || !url.pathname.startsWith(`${basePath}/`)) {
      throw new Error(`Refusing request to a path outside the Action1 API base: ${normalizedPath}`);
    }
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value === undefined || value === null || value === '') {
        continue;
      }
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async getToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.tokenExpiresAt - TOKEN_SAFETY_MARGIN_MS) {
      return this.accessToken;
    }

    if (!this.clientId || !this.clientSecret) {
      throw new Error('Missing ACTION1_CLIENT_ID / ACTION1_CLIENT_SECRET. Set them in the MCP server environment.');
    }

    const url = `${this.baseUrl}/oauth2/token`;
    const response = await this.fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret }).toString(),
      // A 307/308 would re-send client_secret to the redirect target.
      redirect: 'manual',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    assertNotRedirect(response, url);

    const body = (response.ok ? await readResponseBody(response) : await readErrorBody(response)) as
      | { access_token?: string; expires_in?: number }
      | null;

    if (!response.ok || !body?.access_token) {
      throw new Action1HttpError({
        status: response.status,
        url,
        payload: body,
        fallbackMessage: 'Failed to obtain Action1 access token.',
      });
    }

    this.accessToken = body.access_token;
    this.tokenExpiresAt = Date.now() + (body.expires_in ?? 3600) * 1000;
    return this.accessToken;
  }

  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    query?: Record<string, QueryValue>,
    body?: unknown,
  ): Promise<T> {
    const token = await this.getToken();
    const url = this.buildUrl(path, query);
    const headers: Record<string, string> = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    };

    const init: RequestInit = {
      method,
      headers,
      // Never follow redirects with the bearer token.
      redirect: 'manual',
      signal: AbortSignal.timeout(this.timeoutMs),
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    const response = await this.fetchImpl(url, init);

    // A 401 can mean the cached token was revoked server-side — refetch once.
    if (response.status === 401 && this.accessToken) {
      this.accessToken = undefined;
      const retryToken = await this.getToken();
      headers.Authorization = `Bearer ${retryToken}`;
      const retried = await this.fetchImpl(url, init);
      return this.finish<T>(retried, url);
    }

    return this.finish<T>(response, url);
  }

  private async finish<T>(response: Response, url: string): Promise<T> {
    assertNotRedirect(response, url);
    const responseBody = response.ok ? await readResponseBody(response) : await readErrorBody(response);

    if (!response.ok) {
      throw new Action1HttpError({
        status: response.status,
        url,
        payload: responseBody,
        retryAfter: response.headers.get('retry-after') ?? undefined,
        fallbackMessage: typeof responseBody === 'string' ? responseBody : undefined,
      });
    }

    return responseBody as T;
  }
}

async function readResponseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

/** Error bodies are read up to MAX_ERROR_BODY_BYTES; JSON is parsed only when complete. */
async function readErrorBody(response: Response): Promise<unknown> {
  if (!response.body) {
    return null;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let exceeded = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (total + value.byteLength > MAX_ERROR_BODY_BYTES) {
      chunks.push(value.subarray(0, MAX_ERROR_BODY_BYTES - total));
      exceeded = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) {
    return null;
  }
  if (exceeded) {
    return text;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

/** Redirects are not followed (see `redirect: 'manual'`); report them as an error. */
function assertNotRedirect(response: Response, url: string): void {
  if (response.status >= 300 && response.status < 400 && response.status !== 304) {
    void response.body?.cancel().catch(() => undefined);
    throw new Action1HttpError({
      status: response.status,
      url,
      fallbackMessage: 'Action1 API responded with a redirect; redirects are not followed.',
    });
  }
}

function trimTrailingSlash(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') {
    end -= 1;
  }
  return value.slice(0, end);
}

function assertSafeBaseUrl(baseUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`ACTION1_BASE_URL is not a valid URL: ${baseUrl}`);
  }
  if (parsed.protocol === 'https:') {
    return;
  }
  if (parsed.protocol === 'http:' && isLocalHost(parsed.hostname)) {
    return;
  }
  throw new Error(
    `Refusing to send Action1 credentials over ${parsed.protocol}//. Use https:// (loopback http:// is allowed for local mocks).`,
  );
}

function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}
