import { fixedOutputs } from '../fallbacks.js';
import { requestIdFrom, vendorRequestId } from './failure.js';
import { leaksSecret } from '../key-admission.js';
import { SecretRedactor } from '../upstream-http.js';

/**
 * The Action1 client of the embedded gateway (src/gateway.ts). Unlike the MCP
 * server's client (src/action1/client.ts) it reads no ACTION1_* variable:
 * the credentials, the region and the time limit come from the host only. It
 * talks only to the fixed API address of the region, never follows a
 * redirect, never reads the body of an error answer, and puts every token
 * Action1 issues into the instance's redactor before it is used.
 */

/** The Action1 regions and their fixed API addresses (Action1's own list of data centers). */
export const ACTION1_REGIONS = {
  eu: 'https://app.eu.action1.com/api/3.0',
  na: 'https://app.action1.com/api/3.0',
  na2: 'https://app.na-2.action1.com/api/3.0',
  uk: 'https://app.uk.action1.com/api/3.0',
  au: 'https://app.au.action1.com/api/3.0',
} as const;

export type Action1Region = keyof typeof ACTION1_REGIONS;

/** Largest successful JSON answer the gateway reads. */
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;
/** A token is fetched again this long before Action1 says it expires. */
const TOKEN_MARGIN_MS = 60_000;
/** Issued tokens shorter than this are not used: the redactor matches pieces of 6 only in values of 8 or more. */
const MIN_TOKEN_LENGTH = 16;
/** Said for a token that cannot be kept apart from our own texts, and for every later call of that instance. */
export const UNSAFE_TOKEN =
  'Action1 issued an access token that cannot be kept apart from this server’s own texts. It was not used, and this connection passes nothing on; create it again.';

export type QueryValue = string | number | boolean | null | undefined;

/** An HTTP error from Action1, in our own words: the status, our hint and a whole-number retry-after only. */
export class Action1GatewayHttpError extends Error {
  readonly status: number;
  /** Action1's own id for the request, when a response header gives one as a UUID or hex id (src/gateway/failure.ts). */
  readonly requestId?: string;
  constructor(status: number, hint: string | undefined, retryAfter: string | undefined, requestId?: string) {
    super(
      `Action1 API request failed with HTTP ${status}${hint ? `. ${hint}` : ''}${retryAfter ? ` Retry after ${retryAfter} s.` : ''}`,
    );
    this.name = 'Action1HttpError';
    this.status = status;
    const id = vendorRequestId(requestId);
    if (id !== undefined) this.requestId = id;
  }
}

/** A redirect Action1 answered with, refused: our own text (never the Location), the status and request id kept. */
export class Action1GatewayRedirectError extends Error {
  readonly status: number;
  readonly requestId?: string;
  constructor(status: number, method: string, requestId?: string) {
    super(`Action1 API responded with a redirect (HTTP ${status}) for ${method}; redirects are not followed.`);
    this.name = 'Action1RedirectError';
    this.status = status;
    const id = vendorRequestId(requestId);
    if (id !== undefined) this.requestId = id;
  }
}

/** Our own guidance per HTTP status. */
const STATUS_HINTS: Record<number, string> = {
  400: 'Action1 refused the request. Check the ids and values.',
  401: 'Action1 rejected the credentials (invalid, expired or revoked). Retrying will not help.',
  403: 'The Action1 API credentials have no permission for this. Retrying will not help.',
  404: 'Action1 found nothing at this address. Check the ids.',
  429: 'Action1 is throttling requests. Wait and retry later.',
};

/** Our own guidance when the token request fails. */
const TOKEN_HINTS: Record<number, string> = {
  400: 'Action1 rejected the client id or client secret, or they belong to another region. Retrying will not help.',
  401: 'Action1 rejected the client id or client secret, or they belong to another region. Retrying will not help.',
  403: 'Action1 rejected the client id or client secret, or they belong to another region. Retrying will not help.',
  429: 'Action1 is throttling requests. Wait and retry later.',
};

/** System error codes a network error may name: a fixed list, so no other text from a cause is ever shown. */
const SHOWN_NETWORK_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'ENOTFOUND',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
  'CERT_HAS_EXPIRED',
  'ERR_TLS_CERT_ALTNAME_INVALID',
]);

/**
 * Action1 ids (organizations, endpoints, groups, packages, versions, reports)
 * are letters, digits and `_`, `-`, `+`, `~` and inner dots; never a leading
 * dot, so no dot segment can reach the path.
 */
const ACTION1_ID = /^[A-Za-z0-9_+~-][A-Za-z0-9_.+~-]{0,199}$/;
const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

/** One path segment from an id, checked and encoded. */
export function idSegment(value: string, name: string): string {
  if (!ACTION1_ID.test(value)) {
    throw new Error(`Invalid ${name}: expected letters, digits, '_', '-', '+', '~' or inner '.'.`);
  }
  return encodeURIComponent(value);
}

export function cveSegment(value: string): string {
  const upper = value.toUpperCase();
  if (!CVE_ID.test(upper)) throw new Error('Invalid cveId: expected the form CVE-YYYY-NNNN.');
  return upper;
}

export interface Action1GatewayClientOptions {
  clientId: string;
  clientSecret: string;
  region: Action1Region;
  timeoutMs: number;
  redactor: SecretRedactor;
  /** Redacts a value as a whole only (a token that was dropped unused). */
  redactWhole: (value: string) => void;
  fetchImpl?: typeof fetch;
  /** The host's text for the warning before a restart (deploy_updates with allowReboot). */
  rebootMessage?: string;
}

export class Action1GatewayClient {
  readonly baseUrl: string;
  /** The host's text for the warning before a restart, or undefined for Action1's own. */
  readonly rebootMessage?: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly timeoutMs: number;
  private readonly redactor: SecretRedactor;
  private readonly redactWhole: (value: string) => void;
  private readonly fetchImpl: typeof fetch;
  /** The access token, in a box shared with every view of this client (a read tool's view keeps the same token). */
  private readonly tokenBox: {
    token?: { value: string; expiresAt: number };
    pending?: Promise<{ value: string; expiresAt: number }>;
    unsafe?: boolean;
  } = {};

  constructor(options: Action1GatewayClientOptions) {
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.baseUrl = ACTION1_REGIONS[options.region];
    this.redactor = options.redactor;
    this.redactWhole = options.redactWhole;
    this.timeoutMs = options.timeoutMs;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(`timeoutMs must be an integer between 1 and ${MAX_TIMEOUT_MS}.`);
    }
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (options.rebootMessage !== undefined) this.rebootMessage = options.rebootMessage;
  }

  /** True once an issued token could not be kept apart from our own texts: the instance passes nothing on any more. */
  get closed(): boolean {
    return this.tokenBox.unsafe === true;
  }

  async get<T>(path: string, query?: Record<string, QueryValue>): Promise<T> {
    return this.request<T>('GET', path, query);
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, undefined, body);
  }

  buildUrl(path: string, query?: Record<string, QueryValue>): string {
    if (!path.startsWith('/') || path.includes('..') || path.includes('\\') || path.includes('?') || path.includes('#')) {
      throw new Error('Refusing a request path outside the Action1 API.');
    }
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  /** An access token from the client credentials, kept for this instance and added to its redactor. */
  private async accessToken(): Promise<string> {
    if (this.tokenBox.unsafe) throw new Error(UNSAFE_TOKEN);
    const kept = this.tokenBox.token;
    if (kept && Date.now() < kept.expiresAt - TOKEN_MARGIN_MS) return kept.value;
    // One token request at a time per instance: calls made meanwhile wait for the same answer.
    this.tokenBox.pending ??= this.issueToken().finally(() => {
      this.tokenBox.pending = undefined;
    });
    const issued = await this.tokenBox.pending;
    if (this.tokenBox.unsafe) throw new Error(UNSAFE_TOKEN);
    this.tokenBox.token = issued;
    return issued.value;
  }

  /**
   * One token request. Every token Action1 issues (access and refresh) is a secret of this instance before anything
   * else is done with it: redacted by its pieces and as a whole value (raw, URL-encoded, JSON-escaped). A token that
   * cannot be kept apart from this server's own texts (shorter than MIN_TOKEN_LENGTH, or sharing a piece with the fixed
   * fallbacks) is not registered, since its redaction would hit those texts, and is never used: the instance is then
   * closed for good (tokenBox.unsafe), so no answer from Action1 can ever carry it out of this instance.
   */
  private async issueToken(): Promise<{ value: string; expiresAt: number }> {
    const response = await this.send(
      `${this.baseUrl}/oauth2/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret }).toString(),
      },
      'POST',
    );
    if (!response.ok) {
      await discard(response);
      throw new Action1GatewayHttpError(
        response.status,
        Object.hasOwn(TOKEN_HINTS, response.status) ? TOKEN_HINTS[response.status] : 'Action1 did not issue an access token.',
        wholeNumber(response.headers.get('retry-after')),
        requestIdFrom(response.headers),
      );
    }
    const body = (await this.readJson(response, 'POST')) as { access_token?: unknown; refresh_token?: unknown; expires_in?: unknown } | null;
    const issued = [body?.access_token, body?.refresh_token].filter((value): value is string => typeof value === 'string' && value !== '');
    const pieces = new SecretRedactor();
    for (const token of issued) pieces.addSecret(token);
    if (issued.some(token => token.length < MIN_TOKEN_LENGTH) || leaksSecret(fixedOutputs(), pieces)) {
      this.tokenBox.unsafe = true;
      throw new Error(UNSAFE_TOKEN);
    }
    for (const token of issued) {
      this.redactWhole(token);
      this.redactor.addSecret(token);
    }
    if (typeof body?.access_token !== 'string' || body.access_token === '') {
      throw new Error('Action1 did not issue an access token.');
    }
    const seconds = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 3600;
    return { value: body.access_token, expiresAt: Date.now() + seconds * 1000 };
  }

  private async request<T>(method: 'GET' | 'POST', path: string, query?: Record<string, QueryValue>, body?: unknown): Promise<T> {
    const url = this.buildUrl(path, query);
    const token = await this.accessToken();
    const headers: Record<string, string> = { Accept: 'application/json', Authorization: `Bearer ${token}` };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (this.tokenBox.unsafe) throw new Error(UNSAFE_TOKEN);
    const response = await this.send(url, init, method);
    if (this.tokenBox.unsafe) {
      await discard(response);
      throw new Error(UNSAFE_TOKEN);
    }
    if (!response.ok) {
      // The body is never read: Action1's text never becomes part of an error.
      await discard(response);
      throw new Action1GatewayHttpError(
        response.status,
        Object.hasOwn(STATUS_HINTS, response.status) ? STATUS_HINTS[response.status] : undefined,
        wholeNumber(response.headers.get('retry-after')),
        requestIdFrom(response.headers),
      );
    }
    const data = await this.readJson(response, method);
    // Closed while the answer was read: it is not passed on.
    if (this.tokenBox.unsafe) throw new Error(UNSAFE_TOKEN);
    return data as T;
  }

  /** One request: no redirect followed, our time limit, a network failure in our own words. */
  private async send(url: string, init: RequestInit, method: string): Promise<Response> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (error) {
      throw this.transportError(method, error);
    }
    if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
      await discard(response);
      throw new Action1GatewayRedirectError(response.status, method, requestIdFrom(response.headers));
    }
    return response;
  }

  private async readJson(response: Response, method: string): Promise<unknown> {
    let read: { bytes: Uint8Array; exceeded: boolean };
    try {
      read = await readUpTo(response, MAX_RESPONSE_BYTES);
    } catch (error) {
      throw this.transportError(method, error);
    }
    if (read.exceeded) throw new Error(`The Action1 answer exceeds the ${MAX_RESPONSE_BYTES} byte limit (${method}).`);
    const text = new TextDecoder().decode(read.bytes);
    if (!text.trim()) return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`Action1 answered with something that is not JSON (${method}); nothing of it is passed on.`);
    }
  }

  /** A network failure or timeout in our own words: no address, no cause text, only a code from a fixed list. */
  private transportError(method: string, error: unknown): Error {
    if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
      return Object.assign(new Error(`Action1 API request timed out after ${this.timeoutMs} ms (${method}).`), {
        name: 'TimeoutError',
      });
    }
    const shown = causeCodes(error).find(code => SHOWN_NETWORK_CODES.has(code));
    return new Error(`Network error calling the Action1 API (${method})${shown ? ` (${shown})` : ''}.`);
  }
}

async function discard(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}

function causeCodes(error: unknown): string[] {
  const codes: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current !== null && typeof current === 'object'; depth += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string') codes.push(code);
    current = (current as { cause?: unknown }).cause;
  }
  return codes;
}

/** A header value that is a whole number of at most 9 digits, as text; anything else is dropped. */
function wholeNumber(value: string | null): string | undefined {
  return value !== null && /^\d{1,9}$/.test(value.trim()) ? value.trim() : undefined;
}

async function readUpTo(response: Response, limit: number): Promise<{ bytes: Uint8Array; exceeded: boolean }> {
  if (!response.body) return { bytes: new Uint8Array(), exceeded: false };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      return { bytes: new Uint8Array(), exceeded: true };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, exceeded: false };
}
