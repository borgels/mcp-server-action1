import { describe, expect, it } from 'vitest';
import { assertSafePathParam, encodePathParam } from '../src/path-params.js';

describe('path param guard', () => {
  it.each(['', ' ', '.', '..', 'a/b', '../x', 'a\\b', '..\\x', 'a?b', 'a#b', '%2e%2e', '%2E', 'a%2fb', 'a%2Fb', '%5c'])(
    'rejects %j',
    value => {
      expect(() => assertSafePathParam(value, 'id')).toThrow(/Invalid id/);
    },
  );

  it('rejects non-string values', () => {
    expect(() => assertSafePathParam(undefined)).toThrow();
    expect(() => assertSafePathParam({})).toThrow();
  });

  it('accepts ordinary ids and encodes them', () => {
    expect(encodePathParam('abc-123_X')).toBe('abc-123_X');
    expect(encodePathParam(42)).toBe('42');
    expect(encodePathParam('a b:c')).toBe('a%20b%3Ac');
    expect(encodePathParam('...')).toBe('...');
  });
});
