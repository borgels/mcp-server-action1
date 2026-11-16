import { describe, expect, it } from 'vitest';
import {
  ConfigError,
  readEnvBoolean,
  readEnvInteger,
  readEnvList,
  readEnvPort,
  readEnvString,
} from '../src/config-env.js';

describe('config-env', () => {
  it('reads strings, treating blank as unset', () => {
    expect(readEnvString('X', { X: '  v ' })).toBe('v');
    expect(readEnvString('X', { X: '   ' })).toBeUndefined();
    expect(readEnvString('X', {})).toBeUndefined();
  });

  it('reads integers with bounds and never returns NaN', () => {
    expect(readEnvInteger('N', 5, {}, {})).toBe(5);
    expect(readEnvInteger('N', 5, {}, { N: '' })).toBe(5);
    expect(readEnvInteger('N', 5, {}, { N: ' 42 ' })).toBe(42);
    expect(readEnvInteger('N', 5, { min: 0 }, { N: '0' })).toBe(0);
    for (const value of ['abc', '1.5', '1e3', '0', '-3', '0x10', '99999999999999999999']) {
      expect(() => readEnvInteger('N', 5, {}, { N: value })).toThrow(ConfigError);
    }
    expect(() => readEnvInteger('N', 5, { max: 10 }, { N: '11' })).toThrow(/between 1 and 10/);
  });

  it('reads ports', () => {
    expect(readEnvPort('PORT', 3000, { PORT: '65535' })).toBe(65_535);
    expect(() => readEnvPort('PORT', 3000, { PORT: '65536' })).toThrow(/PORT/);
  });

  it('reads booleans strictly', () => {
    expect(readEnvBoolean('B', false, {})).toBe(false);
    expect(readEnvBoolean('B', true, {})).toBe(true);
    expect(readEnvBoolean('B', false, { B: 'TRUE' })).toBe(true);
    expect(readEnvBoolean('B', false, { B: '1' })).toBe(true);
    expect(readEnvBoolean('B', true, { B: 'false' })).toBe(false);
    expect(() => readEnvBoolean('B', false, { B: 'ture' })).toThrow(ConfigError);
  });

  it('reads comma-separated lists', () => {
    expect(readEnvList('L', { L: ' a, ,b ' })).toEqual(['a', 'b']);
    expect(readEnvList('L', {})).toEqual([]);
  });
});
