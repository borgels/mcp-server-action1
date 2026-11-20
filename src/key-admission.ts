/**
 * Which secrets a gateway accepts, and the check every output passes as it
 * leaves (the sink check).
 *
 * The guarantee: nothing that leaves a gateway (a result, an error, the tool
 * list, an audit record or line, a file) contains a piece of
 * KEY_FRAGMENT_LENGTH characters of the key (or, where there is one, of the
 * call's session id). It holds by construction at the sink: every output is
 * checked in its final form, and one that holds a piece is replaced by a
 * fixed fallback. The fallbacks are a small closed set, and a secret that
 * shares a piece with any of them is refused when the gateway is created (or
 * the call starts), so a fallback never holds a piece either.
 *
 * Admission:
 * - printable ASCII only (0x21-0x7E) and at least MIN_KEY_LENGTH characters;
 * - no piece shared with FIXED_CORPUS (every string literal in src/, from
 *   scripts/fixed-corpus.mjs). This is only a cheap first filter: the sink
 *   check above is what guarantees;
 * - no piece shared with the gateway's fixed fallbacks (checked by the
 *   gateway, which knows them).
 *
 * The refusal never quotes the secret: it is a fixed text with every run that
 * shares a piece with the secret masked as "…".
 */
import { FIXED_CORPUS } from './fixed-corpus.generated.js';

export const MIN_KEY_LENGTH = 16;
export const KEY_FRAGMENT_LENGTH = 6;
export const KEY_REFUSED = 'A credential was refused: it is too short, or it shares text with this server’s own texts.';
/** Printable ASCII without the space: what a key or a session id may consist of. */
const PRINTABLE_ASCII = /^[\x21-\x7E]+$/;
/** Values nested deeper than this cannot be checked, and count as leaking. */
const MAX_VISIBLE_DEPTH = 256;

let corpusPieces: Set<string> | undefined;

function pieces(): Set<string> {
  if (!corpusPieces) {
    corpusPieces = new Set();
    for (const text of [...FIXED_CORPUS, KEY_REFUSED]) {
      for (let i = 0; i + KEY_FRAGMENT_LENGTH <= text.length; i += 1) {
        corpusPieces.add(text.slice(i, i + KEY_FRAGMENT_LENGTH));
      }
    }
  }
  return corpusPieces;
}

/** Whether a secret passes the form check and the corpus filter. The gateway also checks its fallbacks. */
export function admitsKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < MIN_KEY_LENGTH || !PRINTABLE_ASCII.test(value)) {
    return false;
  }
  const corpus = pieces();
  for (let i = 0; i + KEY_FRAGMENT_LENGTH <= value.length; i += 1) {
    if (corpus.has(value.slice(i, i + KEY_FRAGMENT_LENGTH))) {
      return false;
    }
  }
  return true;
}

/** KEY_REFUSED with every run that shares a piece with the secret masked, so the refusal holds no piece of it. */
export function keyRefusedText(value: unknown): string {
  return maskedText(KEY_REFUSED, value);
}

/** A fixed text with every run that shares a piece with the secret masked as "…". */
export function maskedText(text: string, value: unknown): string {
  const secret = typeof value === 'string' ? value : '';
  const own = new Set<string>();
  for (let i = 0; i + KEY_FRAGMENT_LENGTH <= secret.length; i += 1) {
    own.add(secret.slice(i, i + KEY_FRAGMENT_LENGTH));
  }
  const covered = new Uint8Array(text.length);
  for (let i = 0; i + KEY_FRAGMENT_LENGTH <= text.length; i += 1) {
    if (own.has(text.slice(i, i + KEY_FRAGMENT_LENGTH))) covered.fill(1, i, i + KEY_FRAGMENT_LENGTH);
  }
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    if (!covered[i]) out += text[i];
    else if (i === 0 || !covered[i - 1]) out += '…';
  }
  return out;
}

/**
 * Every text a host can see of a value: its JSON text, and every string,
 * object key and number in it as it is (JSON escapes quotes and
 * backslashes, so a piece holding one is looked for in the raw strings too).
 * Throws when the value cannot be serialised or is too deep.
 */
export function visibleTexts(value: unknown): string[] {
  const texts: string[] = [];
  const json = JSON.stringify(value);
  if (json !== undefined) texts.push(json);
  const visit = (entry: unknown, depth: number): void => {
    if (depth > MAX_VISIBLE_DEPTH) throw new Error('too deep');
    if (entry instanceof Error) {
      // Not enumerable, so not in the JSON text: read on their own.
      texts.push(String(entry.name), String(entry.message), String(entry.stack ?? ''));
    }
    if (typeof entry === 'string') {
      texts.push(entry);
    } else if (typeof entry === 'number' || typeof entry === 'bigint' || typeof entry === 'boolean') {
      texts.push(String(entry));
    } else if (Array.isArray(entry)) {
      for (const item of entry) visit(item, depth + 1);
    } else if (entry !== null && typeof entry === 'object') {
      for (const [key, item] of Object.entries(entry)) {
        texts.push(key);
        visit(item, depth + 1);
      }
    }
  };
  visit(value, 0);
  return texts;
}

/** Something that knows an instance's secrets: whether a text holds one of them or a piece of one. */
export interface LeakMatcher {
  matches(text: string): boolean;
}

/** The sink check: whether any text a host can see of `value` holds a secret or a piece of one. */
export function leaksSecret(value: unknown, matcher: LeakMatcher): boolean {
  let texts: string[];
  try {
    texts = visibleTexts(value);
  } catch {
    // What cannot be checked does not leave.
    return true;
  }
  return texts.some(text => matcher.matches(text));
}

/**
 * An error in final form, as it leaves a gateway: no `cause`, a `stack` set
 * to `${name}: ${message}` (no frames, paths or function names), and its
 * name, message and stack masked against every given secret, so none of them
 * holds a piece of one. Build a fresh error, then pass it through here.
 */
export function sealedError<E extends Error>(error: E, ...secrets: Array<string | undefined>): E {
  delete (error as { cause?: unknown }).cause;
  let name = String(error.name);
  let message = String(error.message);
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret === '') continue;
    name = maskedText(name, secret);
    message = maskedText(message, secret);
  }
  let stack = `${name}: ${message}`;
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret !== '') stack = maskedText(stack, secret);
  }
  for (const [key, value] of [['name', name], ['message', message], ['stack', stack]] as const) {
    Object.defineProperty(error, key, { value, writable: true, configurable: true, enumerable: false });
  }
  return error;
}
