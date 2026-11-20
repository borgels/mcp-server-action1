/**
 * Redaction for the embedded gateway (src/gateway.ts) and its audit records.
 *
 * Two layers: credential-shaped text (an Authorization header, a Bearer or
 * Basic value, a JSON Web Token, `token=`/`apiKey:`-style assignments) is
 * masked wherever it appears, so a credential the upstream echoes that is not
 * the instance's own never leaves; and the instance's own token (exact value,
 * encoded forms and any piece of FRAGMENT_LENGTH characters) is replaced by
 * the instance's redactor. The MCP server's own error redaction lives in
 * src/errors.ts and is unchanged.
 */
import { REDACTION_MARKER, type SecretRedactor } from './upstream-http.js';

/** Values nested deeper than this are replaced, never passed on. */
export const MAX_REDACT_DEPTH = 64;

const SECRET_PATTERNS = [
  // A scheme word in any case before a value that holds the marker of an earlier redaction: the scheme word and the
  // whole value up to a space, quote, comma or brace, whatever its length.
  /\b(bearer|basic)\s+[^\s"',}]*‹redacted›[^\s"',}]*/gi,
  /Authorization:\s*(Bearer|Basic|Token)\s+[^,\s}]+/gi,
  // A credential-named assignment in text: `X-Api-Key: S`, `api_token=S`, `?access_token=S`, `"apiToken": "S"`.
  /(ACTION1_CLIENT_SECRET|MCP_HTTP_TOKEN|client[-_]?id|(?:x[-_]?)?api[-_]?(?:key|token|secret)|client[-_]?secret|(?:access|refresh|auth|id|session|bearer)[-_]?token|accessToken|apiKey|apiToken|token|password|passwd|secret|product[-_]?key)["']?\s*[:=]\s*["']?[^"',\s}&]+/gi,
  // A marker left by the secrets' redaction (‹redacted›) counts as part of a value, so the rest of it is masked too.
  /\b(Bearer|Basic)\s+(?:[A-Za-z0-9._~+/-]|‹redacted›)+=*/g,
  // Any case ("bearer", "BASIC"), when what follows looks like a token: 8 or more base64 or base64url characters. A
  // short word after "basic" ("basic plan") is left alone; a longer one is masked, a false positive we accept.
  /\b(bearer|basic)\s+(?:[A-Za-z0-9._~+/-]|‹redacted›){8,}=*/gi,
  // A JSON Web Token anywhere (Action1 access tokens are JWTs): three base64url segments, the first a
  // JSON header ("eyJ").
  /\beyJ(?:[A-Za-z0-9_-]|‹redacted›)*\.(?:[A-Za-z0-9_-]|‹redacted›)+\.(?:[A-Za-z0-9_-]|‹redacted›)*/g,
];

/**
 * Credential-shaped text replaced by a marker. Uses no state: the same input
 * always gives the same output.
 */
export function redactCredentialPatterns(value: string): string {
  return SECRET_PATTERNS.reduce(
    (current, pattern) =>
      current.replace(pattern, match => {
        if (/^eyJ/.test(match)) {
          return '[REDACTED]';
        }
        if (/^(Bearer|Basic)\s/i.test(match)) {
          const scheme = match.split(/\s+/)[0] ?? 'Authorization';
          return `${scheme} [REDACTED]`;
        }
        if (/^Authorization:/i.test(match)) {
          return 'Authorization: [REDACTED]';
        }
        // The first separator ends the name: everything after it is the value, which may itself hold `:` or `=`.
        const [, key = 'secret', separator = ':'] = /^(.*?)\s*([:=])/.exec(match) ?? [];
        return `${key.trim()}${separator} [REDACTED]`;
      }),
    value,
  );
}

/**
 * Field names whose value is a credential whatever it looks like: the value of
 * such a field is replaced whole, not only when it matches a pattern.
 */
const CREDENTIAL_NAME =
  /^x?(authorization|proxyauthorization|cookie|setcookie|(access|refresh|id|session|bearer|auth|api|private|secret|subscription|product|license|recovery)(token|key)|token|apisecret|clientsecret|secret|password|passwd|credentials?|twofactorsecret|remembertoken|activationcode)$/;

/** Whether a field name names a credential, however it is written (case, `-`, `_`, spaces, a leading `x-`). */
export function isCredentialField(name: string): boolean {
  return CREDENTIAL_NAME.test(name.toLowerCase().replace(/[-_\s.]/g, ''));
}

/**
 * One text as a gateway may return it: credential-shaped text masked, then the instance's own secrets, then the
 * patterns again (they take the marker as part of a value), until nothing changes.
 */
export function redactText(value: string, redactor: SecretRedactor | undefined): string {
  let result = redactCredentialPatterns(value);
  if (!redactor) return result;
  for (let round = 0; round < 4; round += 1) {
    const next = redactCredentialPatterns(redactor.redact(result));
    if (next === result) break;
    result = next;
  }
  return result;
}

/**
 * A copy of a JSON value with every string, object keys included, passed
 * through redactText, the value of every credential-named field replaced
 * whole, whatever its type, and every number or boolean whose string form
 * would be redacted replaced by the string "‹redacted›". Anything nested
 * deeper than MAX_REDACT_DEPTH is replaced.
 */
export function redactDeep(value: unknown, redactor: SecretRedactor | undefined, depth = 0): unknown {
  if (depth > MAX_REDACT_DEPTH) {
    return '[nested too deep]';
  }
  if (typeof value === 'string') {
    return redactText(value, redactor);
  }
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    const text = String(value);
    if (redactText(text, redactor) !== text) return REDACTION_MARKER;
    return typeof value === 'bigint' ? text : value;
  }
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  const json = (value as { toJSON?: unknown }).toJSON;
  if (typeof json === 'function') {
    return redactDeep(json.call(value), redactor, depth + 1);
  }
  if (Array.isArray(value)) {
    return value.map(entry => redactDeep(entry, redactor, depth + 1));
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      redactText(key, redactor),
      isCredentialField(key) && entry !== null && entry !== undefined
        ? REDACTION_MARKER
        : redactDeep(entry, redactor, depth + 1),
    ]),
  );
}
