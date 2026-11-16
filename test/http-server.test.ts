import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { type AddressInfo, connect, createServer as createNetServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { Action1Client } from '../src/action1/client.js';
import { createServer } from '../src/server.js';
import type { HttpConfig } from '../src/transports/http-helpers.js';
import { type RunningHttpServer, startHttpServer } from '../src/transports/http-server.js';

const TOKEN = 'test-token-0123456789abcdef0123456789';

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function send(
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method: options.method ?? 'POST',
        path: options.path ?? '/mcp',
        headers: options.headers,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', chunk => chunks.push(chunk as Buffer));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end(options.body);
  });
}

const toolsList = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const mcpHeaders = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
};

const seenCallers: Array<string | undefined> = [];

function fakeMcpServer(options: { caller?: string } = {}) {
  seenCallers.push(options.caller);
  const client = new Action1Client({
    clientId: 'test',
    clientSecret: 'test',
    fetchImpl: async () => {
      throw new Error('network access is not allowed in tests');
    },
  });
  return createServer({ client, caller: options.caller });
}

describe('HTTP transport (integration)', () => {
  let running: RunningHttpServer | undefined;
  const logs: string[] = [];

  async function start(overrides: Partial<HttpConfig> = {}): Promise<number> {
    const config: HttpConfig = {
      host: '127.0.0.1',
      port: 0,
      maxBodyBytes: 1024 * 1024,
      httpToken: TOKEN,
      authFailureLimit: 5,
      authFailureWindowMs: 60_000,
      ...overrides,
    };
    running = await startHttpServer(config, { createMcpServer: fakeMcpServer, log: line => logs.push(line) });
    return running.port;
  }

  afterEach(async () => {
    await running?.close();
    running = undefined;
    logs.length = 0;
  });

  it('serves /healthz without auth', async () => {
    const port = await start();
    const reply = await send(port, { method: 'GET', path: '/healthz' });
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body)).toEqual({ status: 'ok' });
  });

  it('returns 401 with WWW-Authenticate without or with a wrong token', async () => {
    const port = await start();
    const missing = await send(port, { headers: mcpHeaders, body: toolsList });
    expect(missing.status).toBe(401);
    expect(missing.headers['www-authenticate']).toBe('Bearer');

    const wrong = await send(port, {
      headers: { ...mcpHeaders, Authorization: 'Bearer wrong-token' },
      body: toolsList,
    });
    expect(wrong.status).toBe(401);
    expect(logs.some(line => line.includes('401') && line.includes('Unauthorized'))).toBe(true);
  });

  it('lists tools with a valid token and sets CORS headers for an allowed origin', async () => {
    const port = await start();
    const reply = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' },
      body: toolsList,
    });
    expect(reply.status).toBe(200);
    expect(reply.body).toContain('"tools"');
    expect(reply.headers['access-control-allow-origin']).toBe('http://localhost:5173');
  });

  it('answers CORS preflight including mcp-protocol-version', async () => {
    const port = await start();
    const reply = await send(port, { method: 'OPTIONS', headers: { Origin: 'http://localhost:5173' } });
    expect(reply.status).toBe(204);
    expect(reply.headers['access-control-allow-headers']).toContain('mcp-protocol-version');
  });

  it('returns 403 for a disallowed origin or Host header', async () => {
    const port = await start();
    const badOrigin = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Origin: 'https://evil.example' },
      body: toolsList,
    });
    expect(badOrigin.status).toBe(403);

    const badHost = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Host: 'rebind.example' },
      body: toolsList,
    });
    expect(badHost.status).toBe(403);
  });

  it('returns 400 with a JSON-RPC parse error for invalid JSON', async () => {
    const port = await start();
    const reply = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}` },
      body: '{not json',
    });
    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toMatchObject({ jsonrpc: '2.0', error: { code: -32700 }, id: null });
  });

  it('returns 413 for an oversized body', async () => {
    const port = await start({ maxBodyBytes: 16 });
    const reply = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}` },
      body: toolsList,
    });
    expect(reply.status).toBe(413);
  });

  it('throttles failing requests with 429 but keeps serving a valid token during an attack', async () => {
    const port = await start({ authFailureLimit: 3 });
    const bad = () => send(port, { headers: { ...mcpHeaders, Authorization: 'Bearer nope' }, body: toolsList });
    const good = () =>
      send(port, { headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}` }, body: toolsList });

    for (let i = 0; i < 3; i++) {
      expect((await bad()).status).toBe(401);
    }
    const blocked = await bad();
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect(blocked.headers['access-control-expose-headers']).toContain('Retry-After');

    for (let i = 0; i < 3; i++) {
      expect((await good()).status).toBe(200);
      expect((await bad()).status).toBe(429);
    }
    expect(logs.filter(line => line.includes('failed authentication attempts'))).toHaveLength(1);
  });

  it('lifts the block when the window ends', async () => {
    const port = await start({ authFailureLimit: 1, authFailureWindowMs: 300 });
    const bad = () => send(port, { headers: { ...mcpHeaders, Authorization: 'Bearer nope' }, body: toolsList });
    expect((await bad()).status).toBe(401);
    expect((await bad()).status).toBe(429);
    await new Promise(resolve => setTimeout(resolve, 400));
    expect((await bad()).status).toBe(401);
  });

  it('never throttles when MCP_AUTH_FAILURE_LIMIT is 0', async () => {
    const port = await start({ authFailureLimit: 0 });
    for (let i = 0; i < 30; i++) {
      const reply = await send(port, { headers: { ...mcpHeaders, Authorization: 'Bearer nope' }, body: toolsList });
      expect(reply.status).toBe(401);
    }
  });

  it('returns 413 for an oversized chunked body without Content-Length', async () => {
    const port = await start({ maxBodyBytes: 16 });
    const reply = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, 'Transfer-Encoding': 'chunked' },
      body: toolsList,
    });
    expect(reply.status).toBe(413);
  });

  it('accepts IPv6 loopback and the bind address as Host, and honours allowedHosts', async () => {
    const port = await start();
    for (const host of [`[::1]:${port}`, `localhost:${port}`, `127.0.0.1:${port}`]) {
      const reply = await send(port, {
        headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Host: host },
        body: toolsList,
      });
      expect(reply.status, host).toBe(200);
    }
    await running?.close();

    const restricted = await start({ allowedHosts: ['mcp.example.com'] });
    const allowed = await send(restricted, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Host: 'mcp.example.com' },
      body: toolsList,
    });
    expect(allowed.status).toBe(200);
    const local = await send(restricted, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, Host: `localhost:${restricted}` },
      body: toolsList,
    });
    expect(local.status).toBe(403);
  });

  it('logs one line and no 500 for an aborted request body', async () => {
    const port = await start();
    await new Promise<void>((resolve, reject) => {
      const socket = connect(port, '127.0.0.1', () => {
        socket.write(
          `POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nAuthorization: Bearer ${TOKEN}\r\n` +
            'Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"jsonrpc":',
          () => setTimeout(() => {
            socket.destroy();
            resolve();
          }, 50),
        );
      });
      socket.on('error', reject);
    });
    await new Promise(resolve => setTimeout(resolve, 100));
    expect(logs.some(line => line.startsWith('[http] 400') && line.includes('aborted'))).toBe(true);
    expect(logs.some(line => line.includes(' 500 '))).toBe(false);
  });

  it('always sends Vary: Origin', async () => {
    const port = await start();
    const reply = await send(port, { headers: { ...mcpHeaders }, body: toolsList });
    expect(reply.headers.vary).toContain('Origin');
  });

  it('refuses insecure configurations in startHttpServer itself', async () => {
    await expect(startHttpServer({ host: '0.0.0.0', port: 0, maxBodyBytes: 1024 })).rejects.toThrow(
      /MCP_HTTP_TOKEN/,
    );
  });

  it('close() resolves and stops accepting connections', async () => {
    const port = await start();
    expect((await send(port, { method: 'GET', path: '/healthz' })).status).toBe(200);
    await running?.close();
    running = undefined;
    await expect(send(port, { method: 'GET', path: '/healthz' })).rejects.toThrow();
  });

  it('passes X-MCP-User to the server for audit logging', async () => {
    const port = await start();
    seenCallers.length = 0;
    const reply = await send(port, {
      headers: { ...mcpHeaders, Authorization: `Bearer ${TOKEN}`, 'X-MCP-User': 'user@example.com' },
      body: toolsList,
    });
    expect(reply.status).toBe(200);
    expect(seenCallers).toEqual(['user@example.com']);
  });

  it('returns 404 for other paths and 405 for other methods', async () => {
    const port = await start();
    expect((await send(port, { method: 'GET', path: '/other' })).status).toBe(404);
    const get = await send(port, { method: 'GET', headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(get.status).toBe(405);
  });
});

describe('HTTP transport entry point', () => {
  const entry = fileURLToPath(new URL('../src/transports/http.ts', import.meta.url));

  function runEntry(env: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
    return new Promise((resolve, reject) => {
      const childEnv: NodeJS.ProcessEnv = { ...process.env };
      for (const name of Object.keys(childEnv)) {
        if (name.startsWith('MCP_') || name.startsWith('ACTION1_') || name === 'HOST' || name === 'PORT') {
          delete childEnv[name];
        }
      }
      const child = spawn(process.execPath, ['--import', 'tsx', entry], {
        env: { ...childEnv, ...env },
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', chunk => {
        stderr += String(chunk);
      });
      const timer = setTimeout(() => child.kill(), 20_000);
      child.on('error', reject);
      child.on('exit', code => {
        clearTimeout(timer);
        resolve({ code, stderr });
      });
    });
  }

  it.each([
    [{ HOST: '0.0.0.0' }, /MCP_HTTP_TOKEN/],
    [{ MCP_ALLOW_ANY_ORIGIN: 'true' }, /MCP_ALLOW_ANY_ORIGIN/],
    [{ MCP_HTTP_TOKEN: 'too-short' }, /at least 32/],
    [{ PORT: 'abc' }, /PORT/],
    [{ ACTION1_TIMEOUT_MS: '30s' }, /ACTION1_TIMEOUT_MS/],
  ])('refuses to start with %o', async (env, message) => {
    const result = await runEntry(env);
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(message);
    expect(result.stderr).toContain('not started');
  }, 30_000);

  it('starts and serves /healthz when run directly', async () => {
    const port = await new Promise<number>((resolve, reject) => {
      const probe = createNetServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const { port: free } = probe.address() as AddressInfo;
        probe.close(() => resolve(free));
      });
    });

    const childEnv: NodeJS.ProcessEnv = { ...process.env };
    for (const name of Object.keys(childEnv)) {
      if (name.startsWith('MCP_') || name.startsWith('ACTION1_') || name === 'HOST') {
        delete childEnv[name];
      }
    }
    const child = spawn(process.execPath, ['--import', 'tsx', entry], {
      env: { ...childEnv, PORT: String(port) },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    try {
      await new Promise<void>((resolve, reject) => {
        let stderr = '';
        const timer = setTimeout(() => reject(new Error(`server did not start: ${stderr}`)), 20_000);
        child.stderr.on('data', chunk => {
          stderr += String(chunk);
          if (stderr.includes('listening')) {
            clearTimeout(timer);
            resolve();
          }
        });
        child.once('exit', code => {
          clearTimeout(timer);
          reject(new Error(`server exited with ${code}: ${stderr}`));
        });
      });
      const reply = await send(port, { method: 'GET', path: '/healthz' });
      expect(reply.status).toBe(200);
    } finally {
      child.kill();
    }
  }, 30_000);
});
