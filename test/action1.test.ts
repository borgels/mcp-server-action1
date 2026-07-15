import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Action1Client } from '../src/action1/client.js';
import { Action1HttpError } from '../src/errors.js';
import { createServer } from '../src/server.js';
import { ACTION1_CAPABILITIES } from '../src/action1/capabilities.js';
import { checkToolPolicy } from '../src/action1/policy.js';
import { listEndpoints, setUpdateApprovals } from '../src/action1/resources.js';

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

const BASE = 'https://app.eu.action1.com/api/3.0';

function makeClient(
  handler: (url: string, init?: RequestInit) => Response | unknown,
  record?: { tokenRequests: number },
): Action1Client {
  const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/oauth2/token')) {
      if (record) {
        record.tokenRequests += 1;
      }
      return new Response(JSON.stringify({ access_token: 'jwt-token', expires_in: 3600, token_type: 'Bearer' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    const result = handler(url, init);
    if (result instanceof Response) {
      return result;
    }
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  return new Action1Client({ clientId: 'id@action1.com', clientSecret: 'secret', fetchImpl });
}

describe('Action1Client', () => {
  it('fetches a token once and reuses it across requests', async () => {
    const record = { tokenRequests: 0 };
    let lastAuth = '';
    const client = makeClient((_url, init) => {
      lastAuth = (init?.headers as Record<string, string>).Authorization ?? '';
      return { items: [], total_items: 0 };
    }, record);

    await client.get('/organizations');
    await client.get('/organizations');

    expect(record.tokenRequests).toBe(1);
    expect(lastAuth).toBe('Bearer jwt-token');
  });

  it('surfaces 429 rate limiting with retry-after', async () => {
    const client = makeClient(
      () =>
        new Response(JSON.stringify({ status: 429, details: { retry_after: 30 } }), {
          status: 429,
          headers: { 'content-type': 'application/json', 'retry-after': '30' },
        }),
    );

    const error = await client.get('/organizations').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Action1HttpError);
    expect((error as Action1HttpError).status).toBe(429);
    expect((error as Action1HttpError).retryAfter).toBe('30');
  });

  it('computes nextFrom from total_items for continuation', async () => {
    const client = makeClient(() => ({ items: [{ id: 1 }, { id: 2 }], total_items: 5, limit: 2 }));
    const page = (await listEndpoints(client, { orgId: 'all', limit: 2 })) as { nextFrom?: number };
    expect(page.nextFrom).toBe(2);

    const lastPage = makeClient(() => ({ items: [{ id: 5 }], total_items: 5 }));
    const done = (await listEndpoints(lastPage, { orgId: 'all', from: 4 })) as { nextFrom?: number };
    expect(done.nextFrom).toBeUndefined();
  });
});

describe('policy', () => {
  it('exposes no execution tools and gates approvals on ACTION1_ENABLE_WRITES', () => {
    expect(checkToolPolicy('action1_list_endpoints').allowed).toBe(true);
    expect(checkToolPolicy('action1_run_automation').allowed).toBe(false);
    expect(checkToolPolicy('action1_create_automation').allowed).toBe(false);

    delete process.env.ACTION1_ENABLE_WRITES;
    expect(checkToolPolicy('action1_set_update_approvals').allowed).toBe(false);
    process.env.ACTION1_ENABLE_WRITES = 'true';
    expect(checkToolPolicy('action1_set_update_approvals').allowed).toBe(true);
  });

  it('refuses approval changes for orgId=all even with writes enabled', async () => {
    process.env.ACTION1_ENABLE_WRITES = 'true';
    const client = makeClient(() => ({}));
    await expect(
      setUpdateApprovals(client, { orgId: 'all', approvals: [{ id: 'x', approval_status: 'Approved' }] }),
    ).rejects.toThrow('ALL organizations');
  });
});

describe('MCP tool surface', () => {
  it('registers every capability as a tool with matching annotations', async () => {
    const server = createServer({ client: makeClient(() => ({})) });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: 't', version: '0' });
    await Promise.all([server.connect(st), mcp.connect(ct)]);

    const { tools } = await mcp.listTools();
    expect(tools.map(t => t.name).sort()).toEqual(ACTION1_CAPABILITIES.map(c => c.id).sort());
    for (const tool of tools) {
      const cap = ACTION1_CAPABILITIES.find(c => c.id === tool.name);
      expect(tool.annotations?.readOnlyHint).toBe(cap?.risk === 'read');
    }
  });

  it('rejects the write tool through the MCP layer when writes are disabled', async () => {
    delete process.env.ACTION1_ENABLE_WRITES;
    const server = createServer({ client: makeClient(() => ({})) });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: 't', version: '0' });
    await Promise.all([server.connect(st), mcp.connect(ct)]);

    const result = await mcp.callTool({
      name: 'action1_set_update_approvals',
      arguments: { orgId: '123', approvals: [{ id: 'x' }] },
    });
    expect(result.isError).toBe(true);
    expect((result.content as Array<{ text: string }>)[0]?.text).toContain('disabled');
  });
});
