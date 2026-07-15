export interface Action1ErrorPayload {
  error?: string;
  message?: string;
  code?: string | number;
}

const SECRET_PATTERNS = [
  /authorization:\s*bearer\s+[^,\s}]+/gi,
  /(clientSecret|ACTION1_CLIENT_SECRET|client_secret|access_token)["']?\s*[:=]\s*["']?[^"',\s}]+/gi,
];

export class Action1HttpError extends Error {
  readonly status: number;
  readonly url: string;
  readonly payload?: Action1ErrorPayload | unknown;
  readonly retryAfter?: string;

  constructor(input: {
    status: number;
    url: string;
    payload?: Action1ErrorPayload | unknown;
    retryAfter?: string;
    fallbackMessage?: string;
  }) {
    super(formatAction1HttpError(input));
    this.name = 'Action1HttpError';
    this.status = input.status;
    this.url = redactSecrets(input.url);
    this.payload = input.payload;
    this.retryAfter = input.retryAfter;
  }
}

export function formatUnknownError(error: unknown): string {
  if (error instanceof Error) {
    return redactSecrets(error.message);
  }

  return redactSecrets(String(error));
}

export function redactSecrets(value: string): string {
  return SECRET_PATTERNS.reduce(
    (current, pattern) =>
      current.replace(pattern, match => {
        const separator = match.includes(':') ? ':' : '=';
        const key = match.split(separator)[0]?.trim() ?? 'secret';
        return `${key}${separator} [REDACTED]`;
      }),
    value,
  );
}

function formatAction1HttpError(input: {
  status: number;
  url: string;
  payload?: Action1ErrorPayload | unknown;
  retryAfter?: string;
  fallbackMessage?: string;
}): string {
  const payload = isAction1ErrorPayload(input.payload) ? input.payload : undefined;
  const parts = [
    `Action1 API request failed with HTTP ${input.status}`,
    payload?.code === undefined ? undefined : `code=${payload.code}`,
    payload?.error,
    payload?.message,
    input.retryAfter ? `retry-after=${input.retryAfter}s` : undefined,
    input.fallbackMessage,
  ].filter(Boolean);

  return redactSecrets(parts.join(' | '));
}

function isAction1ErrorPayload(value: unknown): value is Action1ErrorPayload {
  return typeof value === 'object' && value !== null;
}
