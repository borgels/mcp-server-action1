import type { IncomingMessage } from 'node:http';
import { describe, expect, it } from 'vitest';
import { ConfigError } from '../src/config-env.js';
import {
  assertAllowedHost,
  assertAuthorized,
  AuthFailureLimiter,
  callerIdentity,
  configWarnings,
  getHttpConfig,
  type HttpConfig,
  isLoopbackHost,
  isOriginAllowed,
  tokensEqual,
} from '../src/transports/http-helpers.js';
import { PACKAGE_VERSION } from '../src/version.js';
import packageJson from '../package.json' with { type: 'json' };

function req(headers: Record<string, string> = {}): IncomingMessage {
  return { headers } as IncomingMessage;
}

const TOKEN = 'a'.repeat(32);
const base: HttpConfig = { host: '127.0.0.1', port: 0, maxBodyBytes: 1024 };

describe('http auth hardening', () => {
  it('compares tokens in constant time regardless of length', () => {
    expect(tokensEqual('abc', 'abc')).toBe(true);
    expect(tokensEqual('abc', 'abd')).toBe(false);
    expect(tokensEqual('abc', 'abcdef')).toBe(false);
  });

  it('accepts the configured bearer token and rejects others with WWW-Authenticate', () => {
    const config = { ...base, httpToken: TOKEN };
    expect(() => assertAuthorized(req({ authorization: `Bearer ${TOKEN}` }), config)).not.toThrow();
    expect(() => assertAuthorized(req({ authorization: 'Bearer wrong' }), config)).toThrow('Unauthorized');
    expect(() => assertAuthorized(req(), config)).toThrow(
      expect.objectContaining({ status: 401, headers: { 'WWW-Authenticate': 'Bearer' } }),
    );
  });

  it('treats the Bearer scheme case-insensitively and compares only the token', () => {
    const config = { ...base, httpToken: TOKEN };
    expect(() => assertAuthorized(req({ authorization: `bearer ${TOKEN}` }), config)).not.toThrow();
    expect(() => assertAuthorized(req({ authorization: `BEARER  ${TOKEN}` }), config)).not.toThrow();
    expect(() => assertAuthorized(req({ authorization: TOKEN }), config)).toThrow('Unauthorized');
    expect(() => assertAuthorized(req({ authorization: `Basic ${TOKEN}` }), config)).toThrow('Unauthorized');
    expect(() => assertAuthorized(req({ authorization: `Bearer ${TOKEN} extra` }), config)).toThrow('Unauthorized');
  });
});

describe('getHttpConfig', () => {
  it('defaults to loopback without a token', () => {
    const config = getHttpConfig({});
    expect(config).toMatchObject({ host: '127.0.0.1', port: 3000, maxBodyBytes: 10_485_760 });
    expect(config.httpToken).toBeUndefined();
  });

  it('refuses a non-loopback host without a token', () => {
    expect(() => getHttpConfig({ HOST: '0.0.0.0' })).toThrow(ConfigError);
    expect(() => getHttpConfig({ MCP_HTTP_HOST: '::', MCP_HTTP_TOKEN: '' })).toThrow(/MCP_HTTP_TOKEN/);
    expect(getHttpConfig({ HOST: '0.0.0.0', MCP_HTTP_TOKEN: TOKEN }).httpToken).toBe(TOKEN);
  });

  it('refuses MCP_ALLOW_ANY_ORIGIN=true without a token', () => {
    expect(() => getHttpConfig({ MCP_ALLOW_ANY_ORIGIN: 'true' })).toThrow(/MCP_ALLOW_ANY_ORIGIN/);
    expect(getHttpConfig({ MCP_ALLOW_ANY_ORIGIN: 'true', MCP_HTTP_TOKEN: TOKEN }).allowAnyOrigin).toBe(true);
  });

  it('allows the explicit escape hatch with a warning', () => {
    const config = getHttpConfig({ HOST: '0.0.0.0', MCP_HTTP_ALLOW_UNAUTHENTICATED: 'true' });
    expect(config.allowUnauthenticated).toBe(true);
    expect(configWarnings(config)).toHaveLength(1);
    expect(configWarnings(getHttpConfig({}))).toEqual([]);
  });

  it('requires a token of at least 32 characters', () => {
    expect(() => getHttpConfig({ MCP_HTTP_TOKEN: 'short' })).toThrow(/at least 32/);
    expect(() =>
      getHttpConfig({ MCP_HTTP_TOKEN: 'short', MCP_HTTP_ALLOW_UNAUTHENTICATED: 'true' }),
    ).toThrow(/at least 32/);
  });

  it('refuses tokens with whitespace or non-ASCII characters', () => {
    for (const token of [`${TOKEN}\n`, `${TOKEN}\r`, `${TOKEN} `, ' '.repeat(40), `${TOKEN}æ`]) {
      expect(() => getHttpConfig({ MCP_HTTP_TOKEN: token }), JSON.stringify(token)).toThrow(/printable ASCII/);
    }
    expect(getHttpConfig({ MCP_HTTP_TOKEN: `${TOKEN}-_.~!` }).httpToken).toBe(`${TOKEN}-_.~!`);
  });

  it('accepts MCP_AUTH_FAILURE_LIMIT=0 to disable the limiter', () => {
    expect(getHttpConfig({ MCP_AUTH_FAILURE_LIMIT: '0' }).authFailureLimit).toBe(0);
    expect(() => getHttpConfig({ MCP_AUTH_FAILURE_LIMIT: '-1' })).toThrow(/MCP_AUTH_FAILURE_LIMIT/);
  });

  it('rejects invalid numeric values instead of producing NaN', () => {
    expect(() => getHttpConfig({ PORT: 'abc' })).toThrow(/PORT/);
    expect(() => getHttpConfig({ PORT: '0' })).toThrow(/PORT/);
    expect(() => getHttpConfig({ PORT: '70000' })).toThrow(/PORT/);
    expect(() => getHttpConfig({ MCP_MAX_BODY_BYTES: '10mb' })).toThrow(/MCP_MAX_BODY_BYTES/);
    expect(() => getHttpConfig({ MCP_MAX_BODY_BYTES: '-1' })).toThrow(/MCP_MAX_BODY_BYTES/);
    expect(() => getHttpConfig({ MCP_ALLOW_ANY_ORIGIN: 'maybe' })).toThrow(/MCP_ALLOW_ANY_ORIGIN/);
    expect(getHttpConfig({ PORT: '8080', MCP_MAX_BODY_BYTES: '2048' })).toMatchObject({
      port: 8080,
      maxBodyBytes: 2048,
    });
  });
});

describe('host and origin checks', () => {
  it('recognises loopback hosts', () => {
    for (const host of ['127.0.0.1', '127.1.2.3', 'localhost', '::1', '[::1]']) {
      expect(isLoopbackHost(host)).toBe(true);
    }
    for (const host of ['0.0.0.0', '::', '192.168.1.10', 'example.com']) {
      expect(isLoopbackHost(host)).toBe(false);
    }
  });

  it('only accepts localhost Host headers and the bind address on a loopback bind by default', () => {
    expect(() => assertAllowedHost(req({ host: 'localhost:3000' }), base)).not.toThrow();
    expect(() => assertAllowedHost(req({ host: 'localhost.:3000' }), base)).not.toThrow();
    expect(() => assertAllowedHost(req({ host: '[::1]:3000' }), base)).not.toThrow();
    expect(() => assertAllowedHost(req({ host: 'attacker.example' }), base)).toThrow('Host not allowed');
    expect(() => assertAllowedHost(req(), base)).toThrow('Host not allowed');

    expect(() => assertAllowedHost(req({ host: '127.0.0.2:3000' }), { ...base, host: '127.0.0.2' })).not.toThrow();
    const mapped = { ...base, host: '::ffff:127.0.0.1' };
    expect(isLoopbackHost(mapped.host)).toBe(true);
    expect(() => assertAllowedHost(req({ host: '[::ffff:127.0.0.1]:3000' }), mapped)).not.toThrow();
  });

  it('parses the Host header strictly', () => {
    for (const host of [
      'evil.example@localhost',
      'localhost/evil.example',
      'localhost?x',
      'localhost:abc',
      '127.1',
      '2130706433',
      'localhost:3000:1',
    ]) {
      expect(() => assertAllowedHost(req({ host }), base), host).toThrow('Host not allowed');
    }
  });

  it('uses MCP_ALLOWED_HOSTS when configured and skips the check otherwise on public binds', () => {
    const publicBind = { ...base, host: '0.0.0.0' };
    expect(() => assertAllowedHost(req({ host: 'anything.example' }), publicBind)).not.toThrow();
    const restricted = { ...publicBind, allowedHosts: ['mcp.example.com'] };
    expect(() => assertAllowedHost(req({ host: 'mcp.example.com:443' }), restricted)).not.toThrow();
    expect(() => assertAllowedHost(req({ host: 'mcp.example.com.' }), restricted)).not.toThrow();
    expect(() => assertAllowedHost(req({ host: 'other.example.com' }), restricted)).toThrow('Host not allowed');
  });

  it('validates and normalises MCP_ALLOWED_HOSTS entries at startup', () => {
    expect(getHttpConfig({ MCP_ALLOWED_HOSTS: 'MCP.Example.com., ::1, 10.0.0.5, action1_mcp' }).allowedHosts).toEqual([
      'mcp.example.com',
      '[::1]',
      '10.0.0.5',
      'action1_mcp',
    ]);
    for (const value of ['mcp.example.com:8443', 'https://mcp.example.com', 'mcp.example.com/path', 'a b']) {
      expect(() => getHttpConfig({ MCP_ALLOWED_HOSTS: value }), value).toThrow(/MCP_ALLOWED_HOSTS/);
    }
  });

  it('allows localhost origins by default and configured origins otherwise', () => {
    expect(isOriginAllowed(undefined, {})).toBe(true);
    expect(isOriginAllowed('http://localhost:5173', {})).toBe(true);
    expect(isOriginAllowed('http://[::1]:5173', {})).toBe(true);
    expect(isOriginAllowed('https://evil.example', {})).toBe(false);
    expect(isOriginAllowed('https://app.example', { allowedOrigins: ['https://app.example'] })).toBe(true);
    expect(isOriginAllowed('http://localhost:5173', { allowedOrigins: ['https://app.example'] })).toBe(false);
  });
});

describe('AuthFailureLimiter', () => {
  it('blocks a key after the limit until the window ends', () => {
    const limiter = new AuthFailureLimiter(3, 60_000);
    for (let i = 0; i < 3; i++) {
      expect(limiter.retryAfterSeconds('a', 0)).toBe(0);
      expect(limiter.recordFailure('a', 0)).toBe(i === 2);
    }
    expect(limiter.retryAfterSeconds('a', 1_000)).toBe(59);
    expect(limiter.retryAfterSeconds('b', 1_000)).toBe(0);
    expect(limiter.retryAfterSeconds('a', 60_000)).toBe(0);
  });

  it('keeps memory bounded', () => {
    const limiter = new AuthFailureLimiter(3, 60_000, 100);
    for (let i = 0; i < 1_000; i++) {
      limiter.recordFailure(`key-${i}`, 0);
    }
    expect(limiter.size).toBeLessThanOrEqual(100);
  });
});

describe('callerIdentity', () => {
  it('strips control characters and caps the length', () => {
    expect(callerIdentity(req({ 'x-mcp-user': ' user@example.com\r\n' }))).toBe('user@example.com');
    expect(callerIdentity(req({ 'x-mcp-user': 'a'.repeat(300) }))?.length).toBe(256);
    expect(callerIdentity(req())).toBeUndefined();
  });
});

describe('version', () => {
  it('reports the package.json version', () => {
    expect(PACKAGE_VERSION).toBe(packageJson.version);
  });
});
