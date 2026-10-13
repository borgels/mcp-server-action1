/**
 * Guards for caller-supplied values that are interpolated into URL paths.
 *
 * encodeURIComponent() alone does not neutralise dot segments: `..` and `.`
 * are left untouched and are resolved by URL parsers, which lets a value
 * escape the intended resource path. Encoded separators/dots are rejected as
 * well so they cannot be decoded into traversal sequences further downstream.
 */
const FORBIDDEN_CHARS = /[/\\?#]/;
const ENCODED_TRAVERSAL = /%2e|%2f|%5c/i;

export class InvalidPathParamError extends Error {
  constructor(name: string) {
    super(`Invalid ${name}: must be a single non-empty path segment without '/', '\\', '?', '#', or dot segments.`);
    this.name = 'InvalidPathParamError';
  }
}

export function assertSafePathParam(value: unknown, name = 'path parameter'): string {
  const text = typeof value === 'number' || typeof value === 'bigint' ? String(value) : value;
  if (typeof text !== 'string') {
    throw new InvalidPathParamError(name);
  }
  if (
    text.trim() === '' ||
    text === '.' ||
    text === '..' ||
    FORBIDDEN_CHARS.test(text) ||
    ENCODED_TRAVERSAL.test(text)
  ) {
    throw new InvalidPathParamError(name);
  }
  return text;
}

/** Validate a caller-supplied path segment and percent-encode it. */
export function encodePathParam(value: unknown, name = 'path parameter'): string {
  return encodeURIComponent(assertSafePathParam(value, name));
}
