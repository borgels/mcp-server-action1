import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Action1Client } from '../src/action1/client.js';
import { getEndpoint, listSoftwareRepository, listUpdates, listVulnerabilities } from '../src/action1/resources.js';
import { createServer } from '../src/server.js';

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

function makeClient(seen: string[] = []): Action1Client {
  const fetchImpl = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith('/oauth2/token')) {
      return new Response(JSON.stringify({ access_token: 't', expires_in: 3600 }), { status: 200 });
    }
    seen.push(url);
    return new Response(JSON.stringify({ items: [], total_items: 0 }), { status: 200 });
  }) as unknown as typeof fetch;
  return new Action1Client({ clientId: 'id', clientSecret: 's', fetchImpl });
}

describe('Action1 id validation', () => {
  it.each([
    ['orgId', { orgId: '..', packageId: 'x' }],
    ['orgId', { orgId: '.', packageId: 'x' }],
    ['packageId', { orgId: 'org1', packageId: '..' }],
    ['packageId', { orgId: 'org1', packageId: '%2e%2e' }],
    ['packageId', { orgId: 'org1', packageId: 'a/b' }],
  ])('rejects traversal in %s', async (_name, input) => {
    const seen: string[] = [];
    await expect(listUpdates(makeClient(seen), input)).rejects.toThrow(/Invalid/);
    expect(seen).toEqual([]);
  });

  it('rejects malformed CVE ids', async () => {
    const seen: string[] = [];
    await expect(listVulnerabilities(makeClient(seen), { orgId: 'org1', cveId: '..' })).rejects.toThrow(/cveId/);
    await expect(listVulnerabilities(makeClient(seen), { orgId: 'org1', cveId: 'CVE-..' })).rejects.toThrow(/cveId/);
    expect(seen).toEqual([]);
  });

  it('accepts normal ids', async () => {
    const seen: string[] = [];
    const client = makeClient(seen);
    await listVulnerabilities(client, { orgId: 'org_1', cveId: 'CVE-2024-12345' });
    await listSoftwareRepository(client, { orgId: 'all', packageId: 'Notepad++_1.2.3' });
    await getEndpoint(client, { orgId: 'org1', endpointId: '1f0c2a6e-0000-4000-8000-000000000000' });
    expect(seen.map(u => new URL(u).pathname)).toEqual([
      '/api/3.0/vulnerabilities/org_1/CVE-2024-12345',
      '/api/3.0/software-repository/all/Notepad%2B%2B_1.2.3',
      '/api/3.0/endpoints/managed/org1/1f0c2a6e-0000-4000-8000-000000000000',
    ]);
  });

  it('refuses URLs that resolve outside the requested path', () => {
    const client = makeClient();
    expect(() => client.buildUrl('/updates/org/../../audit/events')).toThrow(/outside/);
    expect(() => client.buildUrl('/updates/org/..\\x')).toThrow(/outside/);
    expect(client.buildUrl('/updates/org')).toBe('https://app.eu.action1.com/api/3.0/updates/org');
  });
});

describe('audit caller identity', () => {
  it('records the caller passed to createServer', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'a1-audit-'));
    process.env.ACTION1_AUDIT_LOG = join(dir, 'audit.log');
    const server = createServer({ client: makeClient(), caller: 'alice@example.com' });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: 't', version: '0' });
    await Promise.all([server.connect(st), mcp.connect(ct)]);
    await mcp.callTool({ name: 'action1_list_organizations', arguments: {} });
    const lines = (await readFile(process.env.ACTION1_AUDIT_LOG, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.every(l => l.caller === 'alice@example.com')).toBe(true);
  });
});
