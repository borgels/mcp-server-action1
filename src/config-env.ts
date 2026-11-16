/**
 * Helpers for reading and validating configuration from environment
 * variables. Invalid values throw a ConfigError with a message naming the
 * variable, so a typo fails at startup instead of silently disabling a limit
 * (e.g. `Number('abc')` is NaN and `x > NaN` is always false).
 */

export type Env = Record<string, string | undefined>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface IntegerOptions {
  min?: number;
  max?: number;
}

/** Returns the trimmed value, or undefined when unset or blank. */
export function readEnvString(name: string, env: Env = process.env): string | undefined {
  const value = env[name];
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

/**
 * Reads a base-10 integer. Unset or blank returns `fallback`; anything that
 * is not a plain integer within [min, max] (default min 1) throws.
 */
export function readEnvInteger(
  name: string,
  fallback: number,
  options: IntegerOptions = {},
  env: Env = process.env,
): number {
  const min = options.min ?? 1;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;
  const value = readEnvString(name, env);
  if (value === undefined) {
    return fallback;
  }

  const parsed = /^[+-]?\d+$/.test(value) ? Number(value) : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new ConfigError(`${name} must be an integer between ${min} and ${max}; got ${describe(value)}.`);
  }
  return parsed;
}

/** Reads a TCP port number (1-65535). */
export function readEnvPort(name: string, fallback: number, env: Env = process.env): number {
  return readEnvInteger(name, fallback, { min: 1, max: 65_535 }, env);
}

const TRUE_VALUES = new Set(['true', '1', 'yes', 'on']);
const FALSE_VALUES = new Set(['false', '0', 'no', 'off']);

/**
 * Reads a boolean flag. Accepts true/false, 1/0, yes/no, on/off (case
 * insensitive). Unset or blank returns `fallback`; anything else throws.
 */
export function readEnvBoolean(name: string, fallback = false, env: Env = process.env): boolean {
  const value = readEnvString(name, env);
  if (value === undefined) {
    return fallback;
  }
  const normalized = value.toLowerCase();
  if (TRUE_VALUES.has(normalized)) {
    return true;
  }
  if (FALSE_VALUES.has(normalized)) {
    return false;
  }
  throw new ConfigError(`${name} must be "true" or "false"; got ${describe(value)}.`);
}

/** Reads a comma-separated list, trimming items and dropping empty ones. */
export function readEnvList(name: string, env: Env = process.env): string[] {
  return (env[name] ?? '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function describe(value: string): string {
  return JSON.stringify(value.length > 40 ? `${value.slice(0, 40)}...` : value);
}
