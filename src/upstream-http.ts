/**
 * The secrets of one embedded gateway instance (src/gateway.ts), and the
 * redactor that masks them. The MCP server keeps its own registry in
 * src/errors.ts; a gateway instance never adds to it.
 */

/** Configured secrets shorter than this are not redacted by value (too likely to hit normal text). */
export const MIN_SECRET_LENGTH = 8;
/** Any piece of a secret this long or longer is redacted, wherever it appears. */
export const FRAGMENT_LENGTH = 6;
/**
 * What a redacted value is replaced by. Its brackets are not ASCII, so it cannot be a piece of a key issued as
 * ASCII.
 */
export const REDACTION_MARKER = '‹redacted›';

/**
 * The secrets of one client, and so of one gateway instance: the exact
 * values (raw, URL-encoded and JSON-escaped) and every fragment of
 * FRAGMENT_LENGTH characters or more of them. Each gateway instance owns its
 * redactor, so a host that runs several tenants in one process never mixes
 * their credentials, and a tenant's token is released with its instance.
 */
export class SecretRedactor {
  private readonly secrets = new Set<string>();
  private readonly fragments = new Set<string>();

  /** Redact this value and every piece of it. Values shorter than MIN_SECRET_LENGTH are ignored. */
  addSecret(value: string | undefined): this {
    if (!value || value.length < MIN_SECRET_LENGTH) {
      return this;
    }
    let encoded = value;
    try {
      encoded = encodeURIComponent(value);
    } catch {
      // A lone surrogate has no URL-encoded form; the other forms are still added.
    }
    for (const form of new Set([value, encoded, JSON.stringify(value).slice(1, -1)])) {
      this.secrets.add(form);
      for (let i = 0; i + FRAGMENT_LENGTH <= form.length; i += 1) {
        this.fragments.add(form.slice(i, i + FRAGMENT_LENGTH));
      }
    }
    return this;
  }

  /** Whether the text contains one of the secrets in any form, or any FRAGMENT_LENGTH-character piece of one. */
  matches(text: string): boolean {
    for (const secret of this.secrets) {
      if (text.includes(secret)) return true;
    }
    if (this.fragments.size === 0) return false;
    for (let i = 0; i + FRAGMENT_LENGTH <= text.length; i += 1) {
      if (this.fragments.has(text.slice(i, i + FRAGMENT_LENGTH))) return true;
    }
    return false;
  }

  /** Every secret value, and every run of text covered by a piece of one, replaced with ‹redacted›. */
  redact(value: string): string {
    let result = value;
    for (const secret of this.secrets) {
      result = result.split(secret).join(REDACTION_MARKER);
    }
    return this.redactFragments(result);
  }

  private redactFragments(text: string): string {
    if (this.fragments.size === 0 || text.length < FRAGMENT_LENGTH) {
      return text;
    }
    let covered: Uint8Array | undefined;
    for (let i = 0; i + FRAGMENT_LENGTH <= text.length; i += 1) {
      if (this.fragments.has(text.slice(i, i + FRAGMENT_LENGTH))) {
        covered ??= new Uint8Array(text.length);
        covered.fill(1, i, i + FRAGMENT_LENGTH);
      }
    }
    if (!covered) {
      return text;
    }
    let out = '';
    let i = 0;
    while (i < text.length) {
      if (covered[i]) {
        out += REDACTION_MARKER;
        while (i < text.length && covered[i]) i += 1;
      } else {
        out += text[i];
        i += 1;
      }
    }
    return out;
  }
}
