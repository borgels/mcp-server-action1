// The sink check (README, "Embedding"): nothing that leaves a gateway holds a piece of 6 characters of the client
// secret. Every output is checked in its final form; known counterexamples and secrets spliced from real outputs.
import { describe, expect, it } from 'vitest';
import { createAction1Gateway } from '../src/gateway.js';
import { visibleTexts } from '../src/key-admission.js';

const CLIENT_ID = 'test-client-0001@action1.com';
const SECRET = 'qqqqwwwwzzzzxxxx1';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** An Action1 that answers the gateway's calls, echoing `echo` (the secret, typically) in its data. */
function action1(echo: string): typeof fetch {
  return async (url, init) => {
    const path = new URL(String(url)).pathname.replace(/^\/api\/3\.0/, '');
    if (path === '/oauth2/token') return json({ access_token: `tok-${echo}-access`, refresh_token: echo, expires_in: 3600 });
    if (path === '/organizations') return json({ total_items: 1, items: [{ id: 'org-1', name: `Org ${echo}`, description: echo, [echo]: echo }] });
    if (path === '/endpoints/managed/org-1') return json({ total_items: 1, items: [{ id: 'ep-1', name: `Bearer ${echo}`, user: `token=${echo}` }] });
    if (path === '/updates/org-1/approvals' && init?.method === 'POST') return json({ details: [{ packages_id: echo, version_id: 'v' }] });
    return json({ developer_message: `not found ${echo}` }, 404);
  };
}

function pieces(value: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 6 <= value.length; i += 1) out.push(value.slice(i, i + 6));
  return out;
}

function leaked(secrets: readonly string[], outputs: unknown[]): string[] {
  const texts = outputs.flatMap(output => (typeof output === 'string' ? [output] : visibleTexts(output)));
  return secrets.flatMap(pieces).filter(piece => texts.some(text => text.includes(piece)));
}

/** Every output of a normal session with `value` as the secret, or the refusal when it is not admitted. */
async function outputs(value: string): Promise<{ refused?: string; outputs: unknown[] }> {
  const records: unknown[] = [];
  let gw: ReturnType<typeof createAction1Gateway>;
  try {
    gw = createAction1Gateway({
      clientId: CLIENT_ID,
      clientSecret: value,
      region: 'eu',
      timeoutMs: 5_000,
      fetchImpl: action1(value),
      policy: { enableWrites: true, audit: record => void records.push(record) },
    });
  } catch (error) {
    return { refused: (error as Error).message, outputs: [(error as Error).message, (error as Error).name, error] };
  }
  const results = [
    await gw.callTool('check_connection', {}, { caller: `person ${value}`, requestId: value }),
    await gw.callTool('list_organizations', {}),
    await gw.callTool('list_endpoints', { orgId: 'org-1' }),
    await gw.callTool('get_endpoint', { orgId: 'org-1', endpointId: 'ep-9' }),
    await gw.callTool('search_capabilities', { query: 'endpoint' }),
    await gw.callTool(value, {}),
    await gw.callTool('set_update_approvals', { orgId: 'org-1', approvalStatus: 'Approved', packages: [{ packageId: 'p', versionId: 'v' }] }),
    await gw.callTool('check_connection', { unknown: value }),
  ];
  return { outputs: [gw.tools, ...results, ...records] };
}

describe('the sink check', () => {
  it('holds for known counterexamples', async () => {
    for (const value of [
      SECRET,
      'qz7":"staV8k2mP9',
      'x"ok":y-0123456789',
      'riskLevelQz7pX2vK9mWb',
      'Zq7pX2visError9mWb4TnR',
      'URI malformedQz7pX2vK9mWb\uD800',
      'Qz7pX2vK9"name":"Org',
      'Qz7pX2vK9mWb"id":"org-1","nam',
    ]) {
      const { refused, outputs: seen } = await outputs(value);
      if (refused !== undefined) expect(refused, value).toMatch(/credential was refused|clientSecret/);
      expect(leaked([value], seen), value).toEqual([]);
    }
  });

  it('holds for secrets spliced from the outputs of a normal session', async () => {
    const base = await outputs(SECRET);
    expect(base.refused).toBeUndefined();
    const texts = base.outputs.flatMap(output => (typeof output === 'string' ? [output] : visibleTexts(output))).filter(text => text.length >= 6);
    let seed = 11;
    const random = (n: number) => {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
      return seed % n;
    };
    const filler = (n: number) => Array.from({ length: n }, () => String.fromCharCode(0x30 + random(43))).join('');
    let admitted = 0;
    for (let round = 0; round < 40; round += 1) {
      const text = texts[random(texts.length)]!;
      const start = random(text.length - 5);
      const window = text.slice(start, start + 6);
      if (!/^[\x21-\x7E]{6}$/.test(window)) continue;
      const value = `${filler(6)}${window}${filler(6)}`;
      const { refused, outputs: seen } = await outputs(value);
      if (refused === undefined) admitted += 1;
      expect(leaked([value], seen), value).toEqual([]);
    }
    expect(admitted).toBeGreaterThan(0);
  });

  it('throws construction errors in final form: no frames or paths in the stack, no cause', () => {
    for (const [clientSecret, region] of [
      ['Qz7way.jsV8k2mP9X', 'moon'],
      ['short', 'eu'],
      [SECRET, ''],
    ] as const) {
      let caught: Error | undefined;
      try {
        createAction1Gateway({ clientId: CLIENT_ID, clientSecret, region: region as never, policy: {} });
      } catch (error) {
        caught = error as Error;
      }
      expect(caught, clientSecret).toBeInstanceOf(Error);
      const stack = String(caught!.stack);
      expect(stack).toBe(`${caught!.name}: ${caught!.message}`);
      expect((caught as { cause?: unknown }).cause).toBeUndefined();
      expect(leaked([clientSecret], [stack, caught!.message, caught!.name, caught])).toEqual([]);
    }
  });
});

describe('credentials Action1 echoes, which are not the instance’s own', () => {
  it('are masked in structuredContent and in the text block', async () => {
    const other = 'ZZotherSESSIONvalue123';
    const fetchImpl: typeof fetch = async url =>
      String(url).endsWith('/oauth2/token')
        ? json({ access_token: 'aaaabbbbccccdddd1111' })
        : json({
            total_items: 1,
            items: [{ id: 'org-1', name: `Authorization: Bearer ${other}`, description: `client_secret=${other} and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl` }],
          });
    const result = await createAction1Gateway({ clientId: CLIENT_ID, clientSecret: SECRET, region: 'eu', fetchImpl }).callTool('list_organizations', {});
    expect(result.isError).toBeUndefined();
    const all = JSON.stringify(result);
    expect(all).not.toContain(other);
    expect(all).not.toContain('eyJhbGciOiJIUzI1NiJ9');
  });
});

describe('the audit records a tool failure by its code', () => {
  async function codes(fetchImpl: typeof fetch, timeoutMs = 5_000): Promise<unknown[]> {
    const records: Array<Record<string, unknown>> = [];
    const gw = createAction1Gateway({
      clientId: CLIENT_ID,
      clientSecret: SECRET,
      region: 'eu',
      fetchImpl,
      timeoutMs,
      policy: { audit: record => void records.push({ ...record }) },
    });
    await gw.callTool('list_organizations', {});
    return records.filter(record => record.action === 'error').map(record => record.error);
  }

  it('writes http_<status>, timeout or error, never the message', async () => {
    expect(await codes(async () => json({ error: 'busy' }, 429))).toEqual(['http_429']);
    expect(await codes(async () => json({ error: 'boom' }, 500))).toEqual(['http_500']);
    expect(
      await codes(
        (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason))),
        20,
      ),
    ).toEqual(['timeout']);
    expect(
      await codes(async () => {
        throw new TypeError('fetch failed', { cause: Object.assign(new Error('x'), { code: 'ECONNREFUSED' }) });
      }),
    ).toEqual(['error']);
  });

  it('writes no caller, request id or unknown tool name of the host to the audit', async () => {
    const records: Array<Record<string, unknown>> = [];
    const gw = createAction1Gateway({
      clientId: CLIENT_ID,
      clientSecret: SECRET,
      region: 'eu',
      fetchImpl: async url => (String(url).endsWith('/oauth2/token') ? json({ access_token: 'aaaabbbbccccdddd1111' }) : json({ total_items: 0, items: [] })),
      policy: { audit: record => void records.push({ ...record }) },
    });
    await gw.callTool('steal_everything_please', {}, { caller: 'mette@example.com', requestId: 'req-from-host-1' });
    await gw.callTool('list_organizations', {}, { caller: 'mette@example.com', requestId: 'req-from-host-1' });
    const text = JSON.stringify(records);
    expect(text).not.toMatch(/mette@example\.com|req-from-host-1|steal_everything/);
    expect(records[0]).toMatchObject({ tool: 'unknown_tool', action: 'rejected' });
  });
});
