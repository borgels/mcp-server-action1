import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  action1GatewayTools,
  action1ToolCatalog,
  ACTION1_REGION_IDS,
  createAction1Gateway,
  GatewayConfigError,
  type Action1GatewayOptions,
  type GatewayJsonObject,
} from '../src/gateway.js';
import { callerPseudonym } from '../src/gateway/audit.js';

const CLIENT_ID = 'test-client-0001@action1.com';
const SECRET_A = 'qqqqwwwwzzzzxxxx1';
const SECRET_B = 'jjjjkkkkvvvvyyyy2';
const ACCESS_TOKEN = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ0ZXN0In0', 'c2lnbmF0dXJlLXBhcnQ'].join('.');
const REFRESH_TOKEN = 'rrrrttttuuuuffff9999';
const EU = 'https://app.eu.action1.com/api/3.0';

beforeEach(() => {
  vi.unstubAllEnvs();
  // The MCP server's variables, set as a shared process would have them: an embedded instance must ignore them all.
  vi.stubEnv('ACTION1_CLIENT_ID', 'env-client-id-must-not-be-used');
  vi.stubEnv('ACTION1_CLIENT_SECRET', 'env-secret-must-not-be-used-0000');
  vi.stubEnv('ACTION1_BASE_URL', 'https://env-base.example.org/api/3.0');
  // Not a number: an instance that read it would throw.
  vi.stubEnv('ACTION1_TIMEOUT_MS', 'not-a-number');
  vi.stubEnv('ACTION1_ENABLE_WRITES', 'true');
  vi.stubEnv('ACTION1_AUDIT_LOG', '/nonexistent/dir/audit.log');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

function json(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json', ...headers } });
}

const ENDPOINT = {
  id: 'ep-1',
  type: 'Endpoint',
  self: '/API/endpoints/managed/org-1/ep-1',
  name: 'Laptop 7',
  device_name: 'LAPTOP-7',
  address: '10.20.30.40',
  MAC: '00:11:22:33:44:55',
  serial: 'SN-123456',
  AD_organization_unit: 'OU=Sales',
  AD_security_groups: ['Sales'],
  custom: [{ name: 'BitLocker key', value: 'recovery' }],
  comment: 'free text',
  OS: 'Windows 11 (24H2)',
  platform: 'Windows',
  online_status: 'SUCCESS',
  status: 'Connected',
  reboot_required: 'No',
  update_status: 'ERROR',
  missing_updates: { critical: 2, other: 5 },
  vulnerabilities: { critical: 1, other: 0 },
  user: 'jdoe',
  last_seen: '2026-11-20 08:00:00',
};
const UPDATE = {
  id: 'pkg-1',
  name: 'Example Browser',
  vendor: 'Example Inc.',
  update_type: 'App',
  versions: [{ id: 'ver-1', version: '1.2.3', approval_status: 'New', security_severity: 'Critical', binary_id: { Windows_64: 'x' }, silent_install_switches: '/S' }],
};

/** An Action1 that answers the token request and every documented read with sample data. */
function action1(overrides: Record<string, () => Response> = {}) {
  return vi.fn<typeof fetch>(async (url, init) => {
    const path = new URL(String(url)).pathname.replace(/^\/api\/3\.0/, '');
    const key = `${init?.method ?? 'GET'} ${path}`;
    if (overrides[key]) return overrides[key]();
    if (key === 'POST /oauth2/token') return json({ access_token: ACCESS_TOKEN, refresh_token: REFRESH_TOKEN, expires_in: 3600, token_type: 'Bearer' });
    if (key === 'GET /organizations') return json({ total_items: 1, items: [{ id: 'org-1', name: 'Head office', self: '/x', type: 'Organization' }] });
    if (key.startsWith('GET /endpoints/managed/') && path.endsWith('/missing-updates')) return json({ total_items: 1, items: [UPDATE] });
    if (key === 'GET /endpoints/managed/org-1') return json({ total_items: 1, items: [ENDPOINT] });
    if (key === 'GET /endpoints/managed/org-1/ep-1') return json(ENDPOINT);
    if (key === 'GET /endpoints/groups/org-1') return json({ total_items: 1, items: [{ id: 'g-1', name: 'Sales', include_filter: [{ field_name: 'name' }] }] });
    if (key === 'GET /endpoints/groups/org-1/g-1') return json({ id: 'g-1', name: 'Sales', uptime_alerts: { user_ids_for_notification: ['u'] } });
    if (key === 'GET /endpoints/groups/org-1/g-1/contents') return json({ total_items: 1, items: [{ ...ENDPOINT, added_via: 'manual' }] });
    if (key === 'GET /updates/org-1') return json({ total_items: 1, items: [UPDATE] });
    if (key === 'GET /updates/org-1/pkg-1') return json(UPDATE);
    if (key === 'POST /updates/org-1/approvals') return json({ status: 'Success', details: [{ packages_id: 'pkg-1', version_id: 'ver-1' }] });
    if (key === 'GET /vulnerabilities/org-1') return json({ total_items: 1, items: [{ cve_id: 'CVE-2026-1234', cvss_score: '9.8', cisa_kev: 'Yes', vector_string: 'AV:N', software: [{ product_name: 'Example Browser', endpoints_count: 3, versions: [{ version: '1.2.0', install_type: 'exe' }] }] }] });
    if (key === 'GET /vulnerabilities/org-1/CVE-2026-1234') return json({ cve_id: 'CVE-2026-1234', description: 'A flaw.' });
    if (key === 'GET /vulnerabilities/org-1/CVE-2026-1234/endpoints') return json({ total_items: 1, items: [{ endpoint_id: 'ep-1', endpoint_name: 'Laptop 7', user: 'jdoe', OS: 'Windows' }] });
    if (key === 'GET /vulnerabilities/org-1/CVE-2026-1234/remediations') return json({ total_items: 1, items: [{ remediation_id: 'r-1', product_name: 'X', remediated_by: { id: 'u-1', display_name: 'Admin', email: 'admin@example.com' } }] });
    if (key.startsWith('GET /installed-software/org-1/data')) return json({ total_items: 1, items: [{ id: 'row-1', fields: { Name: 'Example Browser', Version: '1.2.0', 'Installed For': 'jdoe', 'Install Location': 'C:\\x' }, drilldown: '/x' }] });
    if (key === 'GET /reports/all') return json({ total_items: 1, items: [{ id: 'rep-1', name: 'Missing updates', report_data: '/x' }] });
    if (key === 'GET /reportdata/org-1/rep-1/data') return json({ total_items: 1, items: [{ id: 'r', fields: { Endpoint: 'Laptop 7', 'IP Address': '10.0.0.1', MAC: 'aa', 'Serial Number': 'SN', Email: 'a@example.com', Updates: '3', Nested: { x: 1 } } }] });
    return json({ developer_message: 'not here' }, 404);
  });
}

function gateway(fetchImpl: typeof fetch, extra: Partial<Action1GatewayOptions> = {}) {
  return createAction1Gateway({ clientId: CLIENT_ID, clientSecret: SECRET_A, region: 'eu', fetchImpl, ...extra });
}

function sink() {
  const records: Array<Record<string, unknown>> = [];
  return { records, audit: (record: Readonly<Record<string, unknown>>) => void records.push({ ...record }) };
}

function requestOf(url: unknown, init: RequestInit | undefined): string {
  return `${init?.method ?? 'GET'} ${new URL(String(url)).pathname.replace(/^\/api\/3\.0/, '')}`;
}

function matches(template: string, path: string): boolean {
  const a = template.split('/');
  const b = path.split('/');
  return a.length === b.length && a.every((part, i) => (part.startsWith('{') ? b[i] !== '' : part === b[i]));
}

const CALLS: Record<string, GatewayJsonObject[]> = {
  search_capabilities: [{ query: 'updates' }],
  check_connection: [{}],
  list_organizations: [{}],
  list_endpoints: [{ orgId: 'org-1', rebootRequired: 'Yes', updateStatus: 'ERROR' }],
  get_endpoint: [{ orgId: 'org-1', endpointId: 'ep-1', includeMissingUpdates: true }],
  list_endpoint_groups: [{ orgId: 'org-1' }, { orgId: 'org-1', groupId: 'g-1' }, { orgId: 'org-1', groupId: 'g-1', members: true }],
  list_updates: [{ orgId: 'org-1', approvalStatus: 'New' }, { orgId: 'org-1', packageId: 'pkg-1' }],
  list_vulnerabilities: [
    { orgId: 'org-1' },
    { orgId: 'org-1', cveId: 'CVE-2026-1234' },
    { orgId: 'org-1', cveId: 'CVE-2026-1234', detail: 'endpoints' },
    { orgId: 'org-1', cveId: 'CVE-2026-1234', detail: 'remediations' },
  ],
  get_installed_software: [{ orgId: 'org-1' }, { orgId: 'org-1', endpointId: 'ep-1' }],
  list_reports: [{}],
  get_report_data: [{ orgId: 'org-1', reportId: 'rep-1' }],
  set_update_approvals: [{ orgId: 'org-1', approvalStatus: 'Approved', packages: [{ packageId: 'pkg-1', versionId: 'ver-1' }] }],
};

describe('Action1 gateway surface', () => {
  it('has the agreed tool set: reads enabled by default, one write, nothing broad, nothing that runs or deletes', () => {
    expect(action1GatewayTools.map(tool => tool.name)).toEqual(Object.keys(CALLS));
    const writes = action1ToolCatalog.filter(tool => tool.riskLevel !== 'read');
    expect(writes.map(tool => tool.name)).toEqual(['set_update_approvals']);
    expect(writes.every(tool => tool.riskLevel === 'write' && !tool.enabledByDefault)).toBe(true);
    expect(action1ToolCatalog.filter(tool => tool.riskLevel === 'read').every(tool => tool.enabledByDefault)).toBe(true);
    expect(action1ToolCatalog.some(tool => tool.broad)).toBe(false);
    const all = JSON.stringify(action1ToolCatalog.map(tool => [tool.name, tool.upstream]));
    for (const word of ['script', 'automation', 'software-repository', 'reboot', 'install"', 'uninstall', 'delete', 'remote-session', 'audit']) {
      expect(all.toLowerCase()).not.toContain(word);
    }
    for (const tool of action1ToolCatalog) {
      for (const op of tool.upstream) expect(op.method === 'GET' || op.path === '/oauth2/token' || tool.riskLevel === 'write').toBe(true);
    }
  });

  it('has a deeply frozen catalog equal to the tool definitions, with strict input schemas', () => {
    expect(Object.isFrozen(action1ToolCatalog)).toBe(true);
    for (const entry of action1ToolCatalog) {
      expect(Object.isFrozen(entry) && Object.isFrozen(entry.upstream) && Object.isFrozen(entry.inputSchema)).toBe(true);
      const { upstream: _u, broad: _b, ...definition } = entry;
      expect(definition).toEqual(action1GatewayTools.find(tool => tool.name === entry.name));
      expect(entry.inputSchema.additionalProperties).toBe(false);
    }
    expect(() => (action1ToolCatalog as unknown as unknown[]).push({})).toThrow();
  });

  it('offers the five regions of Action1', () => {
    expect(ACTION1_REGION_IDS).toEqual(['eu', 'na', 'na2', 'uk', 'au']);
  });
});

describe('Action1 gateway upstream requests', () => {
  it('sends only the requests the catalog declares for each tool, and reaches each of them', async () => {
    for (const entry of action1ToolCatalog) {
      const fetchImpl = action1();
      const g = gateway(fetchImpl, { policy: { enableWrites: true } });
      for (const input of CALLS[entry.name] ?? []) {
        const result = await g.callTool(entry.name, input);
        expect(result.isError, `${entry.name} ${JSON.stringify(result)}`).toBeUndefined();
      }
      const seen = fetchImpl.mock.calls.map(([url, init]) => requestOf(url, init));
      for (const request of seen) {
        const [method, path] = request.split(' ');
        expect(entry.upstream.some(op => op.method === method && matches(op.path, path!)), `${entry.name}: ${request}`).toBe(true);
      }
      for (const op of entry.upstream) {
        expect(seen.some(request => request.split(' ')[0] === op.method && matches(op.path, request.split(' ')[1]!)), `${entry.name} ${op.path}`).toBe(true);
      }
      for (const [url] of fetchImpl.mock.calls) expect(String(url).startsWith(`${EU}/`)).toBe(true);
    }
  });

  it('gets a token with the given credentials, then calls with it, never following a redirect', async () => {
    const fetchImpl = action1();
    await gateway(fetchImpl).callTool('list_organizations', {});
    const [tokenUrl, tokenInit] = fetchImpl.mock.calls[0]!;
    expect(String(tokenUrl)).toBe(`${EU}/oauth2/token`);
    expect(String(tokenInit?.body)).toBe(new URLSearchParams({ client_id: CLIENT_ID, client_secret: SECRET_A }).toString());
    const [, init] = fetchImpl.mock.calls[1]!;
    expect((init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    for (const [, each] of fetchImpl.mock.calls) expect(each?.redirect).toBe('manual');
  });

  it('uses the region’s fixed address', async () => {
    for (const [region, host] of [['na', 'app.action1.com'], ['na2', 'app.na-2.action1.com'], ['uk', 'app.uk.action1.com'], ['au', 'app.au.action1.com']] as const) {
      const fetchImpl = action1();
      await gateway(fetchImpl, { region }).callTool('list_organizations', {});
      for (const [url] of fetchImpl.mock.calls) expect(new URL(String(url)).host).toBe(host);
    }
  });

  it('sends approvals in Action1’s shape for one organization, and refuses "all" before anything is sent', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl, { policy: { enableWrites: true } });
    const result = await g.callTool('set_update_approvals', CALLS.set_update_approvals![0]!);
    expect(result.structuredContent).toEqual({ approvalStatus: 'Approved', packages: [{ packages_id: 'pkg-1', version_id: 'ver-1' }] });
    const post = fetchImpl.mock.calls.find(([url]) => String(url).endsWith('/approvals'))!;
    expect(JSON.parse(String(post[1]?.body))).toEqual([{ approval_status: 'Approved', packages: [{ packages_id: 'pkg-1', version_id: 'ver-1' }] }]);

    const before = fetchImpl.mock.calls.length;
    const all = await g.callTool('set_update_approvals', { orgId: 'all', approvalStatus: 'Approved', packages: [{ packageId: 'pkg-1', versionId: 'ver-1' }] });
    expect(all.isError).toBe(true);
    expect(fetchImpl.mock.calls.slice(before).some(([url]) => String(url).endsWith('/approvals'))).toBe(false);
  });

  it('maps the filters to Action1’s query names and caps the page size', async () => {
    const fetchImpl = action1();
    await gateway(fetchImpl).callTool('list_endpoints', { orgId: 'org-1', rebootRequired: 'Yes', onlineStatus: 'ERROR', search: 'lap', limit: 100 });
    const url = new URL(String(fetchImpl.mock.calls[1]![0]));
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: '100', from: '0', filter: 'lap', online_status: 'ERROR', reboot_required: 'Yes' });
    expect((await gateway(action1()).callTool('list_endpoints', { orgId: 'org-1', limit: 500 })).isError).toBe(true);
  });

  it('refuses ids that are not Action1 ids before anything is sent', async () => {
    const fetchImpl = action1();
    for (const input of [{ orgId: '../x' }, { orgId: 'org-1/../../x' }, { orgId: '.hidden' }]) {
      const result = await gateway(fetchImpl).callTool('list_endpoints', input);
      expect(result.isError).toBe(true);
    }
    const cve = await gateway(fetchImpl).callTool('list_vulnerabilities', { orgId: 'org-1', cveId: 'CVE-26-x' });
    expect(cve.isError).toBe(true);
    expect(fetchImpl.mock.calls.filter(([url]) => !String(url).endsWith('/oauth2/token'))).toEqual([]);
  });
});

describe('Action1 gateway answers', () => {
  it('never returns IP or MAC addresses, serials, directory groups, custom attributes or comments of an endpoint', async () => {
    for (const [tool, input] of [
      ['list_endpoints', { orgId: 'org-1' }],
      ['get_endpoint', { orgId: 'org-1', endpointId: 'ep-1' }],
      ['list_endpoint_groups', { orgId: 'org-1', groupId: 'g-1', members: true }],
    ] as const) {
      const result = await gateway(action1()).callTool(tool, input);
      const text = JSON.stringify(result);
      for (const secret of ['10.20.30.40', '00:11:22:33:44:55', 'SN-123456', 'OU=Sales', 'BitLocker', 'free text', '"self"']) {
        expect(text, `${tool} ${secret}`).not.toContain(secret);
      }
      expect(text).toContain('Laptop 7');
      expect(text).toContain('"critical":2');
    }
  });

  it('leaves out group filters, install switches, mails of remediations and the private columns of reports', async () => {
    const text = async (tool: string, input: GatewayJsonObject) => JSON.stringify(await gateway(action1()).callTool(tool, input));
    expect(await text('list_endpoint_groups', { orgId: 'org-1' })).not.toContain('include_filter');
    expect(await text('list_endpoint_groups', { orgId: 'org-1', groupId: 'g-1' })).not.toContain('user_ids');
    const updates = await text('list_updates', { orgId: 'org-1' });
    expect(updates).toContain('"approval_status":"New"');
    expect(updates).not.toContain('silent_install');
    expect(updates).not.toContain('binary_id');
    const remediations = await text('list_vulnerabilities', { orgId: 'org-1', cveId: 'CVE-2026-1234', detail: 'remediations' });
    expect(remediations).toContain('Admin');
    expect(remediations).not.toContain('admin@example.com');
    const software = await text('get_installed_software', { orgId: 'org-1' });
    expect(software).toContain('Example Browser');
    expect(software).not.toContain('Installed For');
    expect(software).not.toContain('C:');
    const report = await text('get_report_data', { orgId: 'org-1', reportId: 'rep-1' });
    expect(report).toContain('Laptop 7');
    expect(report).toContain('"Updates":"3"');
    for (const hidden of ['10.0.0.1', 'IP Address', 'MAC', 'Serial', 'a@example.com', 'Nested']) expect(report).not.toContain(hidden);
  });

  it('puts the summary, then the data as compact JSON, in the text block, exactly the structured content', async () => {
    const result = await gateway(action1()).callTool('list_organizations', {});
    expect(result.content[0]!.text).toBe(`Action1 organizations.\n\n${JSON.stringify(result.structuredContent)}`);
    expect(result.structuredContent).toEqual({ items: [{ id: 'org-1', name: 'Head office' }], from: 0, total: 1 });
  });

  it('redacts the secret, the client id and the tokens Action1 issued wherever they appear', async () => {
    const echo = { total_items: 1, items: [{ id: 'org-1', name: `x ${SECRET_A} y`, description: `${ACCESS_TOKEN} ${REFRESH_TOKEN} ${CLIENT_ID}` }] };
    const result = await gateway(action1({ 'GET /organizations': () => json(echo) })).callTool('list_organizations', {});
    const text = JSON.stringify(result);
    for (const secret of [SECRET_A, ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_ID, ACCESS_TOKEN.slice(10, 22), REFRESH_TOKEN.slice(3, 12)]) {
      expect(text).not.toContain(secret);
    }
  });
});

describe('Action1 gateway answers, closed against bypasses', () => {
  it('keeps only named report columns, and no mail, IP or MAC address in any of them', async () => {
    const row = {
      id: 'r',
      fields: {
        IPv4: '192.0.2.42',
        Owner: 'person@example.org',
        Notes: 'SN-TEST-01',
        Version: '2.51.0.2', // hygiene:allow (a version, not an address)
        'Last Seen': '2026-11-20 08:00:00',
        Endpoint: '192.0.2.43',
        Name: 'mette@example.org',
        Status: '00:11:22:33:44:55',
        OS: 'fe80:0:0:0:0:0:0:1',
        'Installed Version': '00:11:22:33:44:56',
        'Latest Version': 'person@localhost',
      },
    };
    const result = await gateway(action1({ 'GET /reportdata/org-1/rep-1/data': () => json({ total_items: 1, items: [row] }) })).callTool(
      'get_report_data',
      { orgId: 'org-1', reportId: 'rep-1' },
    );
    expect(result.structuredContent).toEqual({ items: [{ id: 'r', fields: { Version: '2.51.0.2', 'Last Seen': '2026-11-20 08:00:00' } }], from: 0, total: 1 }); // hygiene:allow (a version, not an address)
    for (const hidden of ['192.0.2', 'example.org', 'SN-TEST', '00:11:22', 'fe80']) expect(JSON.stringify(result)).not.toContain(hidden);
  });

  it('leaves out a logged-in user name that is a mail address', async () => {
    const endpoint = { ...ENDPOINT, user: 'person@localhost' };
    for (const [key, body, tool, input] of [
      ['GET /endpoints/managed/org-1', { total_items: 1, items: [endpoint] }, 'list_endpoints', { orgId: 'org-1' }],
      ['GET /endpoints/managed/org-1/ep-1', endpoint, 'get_endpoint', { orgId: 'org-1', endpointId: 'ep-1' }],
      [
        'GET /vulnerabilities/org-1/CVE-2026-1234/endpoints',
        { total_items: 1, items: [{ endpoint_id: 'ep-1', user: 'person@example.org' }] },
        'list_vulnerabilities',
        { orgId: 'org-1', cveId: 'CVE-2026-1234', detail: 'endpoints' },
      ],
    ] as const) {
      const result = await gateway(action1({ [key]: () => json(body) })).callTool(tool, input as GatewayJsonObject);
      expect(result.isError, tool).toBeUndefined();
      expect(JSON.stringify(result), tool).not.toMatch(/person@/);
    }
  });
});

describe('Action1 gateway access tokens', () => {
  const tokens = (fetchImpl: ReturnType<typeof action1>) => fetchImpl.mock.calls.filter(([url]) => String(url).endsWith('/oauth2/token')).length;

  it('asks for a token once per instance, also across read tools, and again when it is about to expire', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl);
    await g.callTool('list_organizations', {});
    await g.callTool('list_endpoints', { orgId: 'org-1' });
    await g.callTool('list_reports', {});
    expect(tokens(fetchImpl)).toBe(1);
    const short = action1({ 'POST /oauth2/token': () => json({ access_token: ACCESS_TOKEN, expires_in: 30 }) });
    const h = gateway(short);
    await h.callTool('list_organizations', {});
    await h.callTool('list_organizations', {});
    expect(tokens(short)).toBe(2);
  });

  it('never uses a token it cannot keep apart from its own texts, and then passes nothing from Action1 on', async () => {
    const unsafe = [
      { access_token: 'zz-credential-of-this-zz' },
      { access_token: '"isError":true,"content"' },
      { access_token: 'a' },
      { access_token: 'q7Z' },
      { access_token: ACCESS_TOKEN, refresh_token: 'k7' },
      { refresh_token: 'credential-of-this-instance' },
    ];
    for (const answer of unsafe) {
      const echo = String(answer.access_token ?? answer.refresh_token);
      let first = true;
      const fetchImpl = action1({
        'POST /oauth2/token': () => {
          const reply = first ? json(answer) : json({ access_token: ACCESS_TOKEN });
          first = false;
          return reply;
        },
        'GET /organizations': () => json({ total_items: 1, items: [{ id: 'org-1', name: `x ${echo} y` }] }),
      });
      const records: Array<Record<string, unknown>> = [];
      const g = gateway(fetchImpl, { policy: { audit: record => void records.push({ ...record }) } });
      const results = [await g.callTool('list_organizations', {}), await g.callTool('list_organizations', {}), await g.callTool('check_connection', {})];
      for (const result of results) {
        expect(result.isError, echo).toBe(true);
        expect(result.content[0]!.text, echo).toMatch(/cannot be kept apart/);
      }
      // One token request, and nothing else: no answer of Action1's can carry the token out.
      expect(fetchImpl.mock.calls.map(([url]) => new URL(String(url)).pathname), echo).toEqual(['/api/3.0/oauth2/token']);
      for (const [, init] of fetchImpl.mock.calls) expect(JSON.stringify(init?.headers ?? {})).not.toContain(`Bearer ${echo}`);
      expect(records.every(record => record.auditRecord === undefined), echo).toBe(true);
    }
  });

  it('makes one token request for calls at the same time, and passes nothing on once a token closed the instance', async () => {
    const colliding = 'zz-credential-of-this-zz';
    let release!: () => void;
    const gate = new Promise<void>(resolve => (release = resolve));
    let tokens = 0;
    const fetchImpl = action1({
      'POST /oauth2/token': () => {
        tokens += 1;
        return json({ access_token: tokens === 1 ? colliding : ACCESS_TOKEN });
      },
      'GET /organizations': () => json({ total_items: 1, items: [{ id: 'org-1', name: colliding }] }),
    });
    const slow: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/oauth2/token')) await gate;
      return fetchImpl(url, init);
    };
    const g = gateway(slow);
    const both = Promise.all([g.callTool('list_organizations', {}), g.callTool('list_organizations', {}), g.callTool('list_endpoints', { orgId: 'org-1' })]);
    for (let i = 0; i < 20; i += 1) await new Promise(resolve => setImmediate(resolve));
    release();
    for (const result of await both) {
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toContain(colliding);
    }
    expect(tokens).toBe(1);
    expect(fetchImpl.mock.calls.filter(([url]) => !String(url).endsWith('/oauth2/token'))).toEqual([]);

    // A call that already read its answer and waits for its finish audit passes nothing on if another call's token
    // request closes the instance meanwhile.
    let renewals = 0;
    const renewing = action1({
      'POST /oauth2/token': () => {
        renewals += 1;
        return json({ access_token: renewals === 1 ? ACCESS_TOKEN : colliding, expires_in: 61 });
      },
      'GET /organizations': () => json({ total_items: 1, items: [{ id: 'org-1', name: colliding }] }),
    });
    let hold!: () => void;
    const held = new Promise<void>(resolve => (hold = resolve));
    let waiting = false;
    const audit = async (record: Readonly<Record<string, unknown>>) => {
      if (record.action === 'finish' && !waiting) {
        waiting = true;
        await held;
      }
    };
    const k = gateway(renewing, { policy: { audit } });
    const first = k.callTool('list_organizations', {});
    for (let i = 0; i < 50 && !waiting; i += 1) await new Promise(resolve => setImmediate(resolve));
    expect(waiting).toBe(true);
    vi.useFakeTimers({ now: Date.now() + 5_000, toFake: ['Date'] });
    try {
      const second = await k.callTool('list_organizations', {});
      expect(second.content[0]!.text).toMatch(/cannot be kept apart/);
    } finally {
      vi.useRealTimers();
    }
    hold();
    const late = await first;
    expect(late.isError).toBe(true);
    expect(JSON.stringify(late)).not.toContain(colliding);

    // Concurrent reads on a good token share one token request too.
    const good = action1();
    const h = gateway(good);
    await Promise.all([h.callTool('list_organizations', {}), h.callTool('list_reports', {}), h.callTool('check_connection', {})]);
    expect(good.mock.calls.filter(([url]) => String(url).endsWith('/oauth2/token'))).toHaveLength(1);
  });

  it('never passes on a refresh token issued without an access token, nor an echo of an encoded token or client id', async () => {
    const refresh = 'rf9Xw2Lk5Pm8Qa3Zt6Yb';
    let first = true;
    const fetchImpl = action1({
      'POST /oauth2/token': () => {
        const reply = first ? json({ refresh_token: refresh }) : json({ access_token: ACCESS_TOKEN });
        first = false;
        return reply;
      },
      'GET /organizations': () =>
        json({
          total_items: 1,
          items: [{ id: 'org-1', name: `x ${refresh} ${encodeURIComponent(CLIENT_ID)} ${encodeURIComponent(ACCESS_TOKEN)}`, description: JSON.stringify(refresh).slice(1, -1) }],
        }),
    });
    const g = gateway(fetchImpl);
    expect((await g.callTool('list_organizations', {})).isError).toBe(true);
    const later = JSON.stringify(await g.callTool('list_organizations', {}));
    for (const form of [refresh, encodeURIComponent(CLIENT_ID), encodeURIComponent(ACCESS_TOKEN)]) expect(later).not.toContain(form);
  });
});

describe('Action1 gateway errors', () => {
  it('starts an error with the HTTP status in our own words and never carries Action1’s body', async () => {
    const fetchImpl = action1({ 'GET /organizations': () => json({ developer_message: 'Mette Jensen is not allowed' }, 403, { 'retry-after': '5' }) });
    const result = await gateway(fetchImpl).callTool('list_organizations', {});
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toMatch(/^Action1 API request failed with HTTP 403\. /);
    expect(result.content[0]!.text).not.toContain('Mette');
  });

  it('words a refused token request as refused credentials, without the body', async () => {
    const result = await gateway(action1({ 'POST /oauth2/token': () => json({ error: 'invalid_client secret qqqq' }, 401) })).callTool('check_connection', {});
    expect(result.content[0]!.text).toMatch(/^Action1 API request failed with HTTP 401\. Action1 rejected the client id or client secret/);
    expect(result.content[0]!.text).not.toContain('invalid_client');
  });

  it('never follows a redirect and refuses an answer that is not JSON', async () => {
    const redirect = await gateway(
      action1({ 'GET /organizations': () => new Response(null, { status: 302, headers: { location: 'https://elsewhere.example.org/' } }) }),
    ).callTool('list_organizations', {});
    expect(redirect.content[0]!.text).toMatch(/redirect/);
    expect(redirect.content[0]!.text).not.toContain('elsewhere');
    const html = await gateway(action1({ 'GET /organizations': () => new Response('<html>Mette</html>', { status: 200 }) })).callTool(
      'list_organizations',
      {},
    );
    expect(html.content[0]!.text).toMatch(/not JSON/);
    expect(html.content[0]!.text).not.toContain('Mette');
  });

  it('words a network failure and a timeout itself, with no cause text', async () => {
    const failing = vi.fn<typeof fetch>(async () => {
      throw Object.assign(new Error('connect to 10.1.2.3 failed'), { cause: { code: 'ECONNREFUSED' } });
    });
    const result = await gateway(failing).callTool('check_connection', {});
    expect(result.content[0]!.text).toBe('Network error calling the Action1 API (POST) (ECONNREFUSED).');
    const slow = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'TimeoutError' })))),
    );
    const timed = await gateway(slow, { timeoutMs: 20 }).callTool('check_connection', {});
    expect(timed.content[0]!.text).toBe('Action1 API request timed out after 20 ms (POST).');
  });
});

describe('Action1 gateway connection settings', () => {
  it('uses only the credentials and region it was given, never ACTION1_*', async () => {
    const fetchImpl = action1();
    const records = sink();
    const g = gateway(fetchImpl, { policy: { audit: records.audit } });
    expect((await g.callTool('set_update_approvals', CALLS.set_update_approvals![0]!)).isError).toBe(true);
    await g.callTool('list_organizations', {});
    const sent = JSON.stringify(fetchImpl.mock.calls);
    expect(sent).not.toContain('env-');
    for (const [url] of fetchImpl.mock.calls) expect(String(url).startsWith(EU)).toBe(true);
  });

  it('requires the client id, the secret and a known region, and refuses them without quoting them', () => {
    expect(() => createAction1Gateway({ clientId: CLIENT_ID, clientSecret: '', region: 'eu' })).toThrow(GatewayConfigError);
    expect(() => createAction1Gateway({ clientId: '', clientSecret: SECRET_A, region: 'eu' })).toThrow(/clientId/);
    expect(() => createAction1Gateway({ clientId: 'has space in it', clientSecret: SECRET_A, region: 'eu' })).toThrow(/clientId/);
    expect(() => createAction1Gateway({ clientId: CLIENT_ID, clientSecret: SECRET_A, region: 'mars' as never })).toThrow(/region must be one of/);
    for (const refused of ['short-secret', 'Action1 API request failed', 'xx Unsupported Action1 gateway tool.']) {
      let message = '';
      try {
        createAction1Gateway({ clientId: CLIENT_ID, clientSecret: refused, region: 'eu' });
      } catch (error) {
        message = (error as Error).message;
        expect((error as Error).stack).not.toContain('at ');
      }
      expect(message).not.toBe('');
      for (let i = 0; i + 6 <= refused.length; i += 1) expect(message).not.toContain(refused.slice(i, i + 6));
    }
  });
});

describe('Action1 gateway input and policy', () => {
  it('validates input before anything is sent and refuses unknown fields and tools', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl, { policy: { enableWrites: true } });
    const unknownField = await g.callTool('list_organizations', { filter: 'x' });
    expect(unknownField.content[0]!.text).toMatch(/^Invalid input for list_organizations/);
    const badApproval = await g.callTool('set_update_approvals', { orgId: 'org-1', approvalStatus: 'Approved', packages: [{ id: 'x', version: '1', approval_status: 'Approved' }] });
    expect(badApproval.isError).toBe(true);
    for (const name of ['run_script', 'list_scripts', 'list_automations', 'list_software_repository', 'get_audit_log', 'action1_run_script', 'nope']) {
      expect((await g.callTool(name, {})).content[0]!.text).toBe('Unsupported Action1 gateway tool.');
    }
    expect((await g.callTool('ACTION1_LIST_ORGANIZATIONS', {})).isError).toBeUndefined();
    expect(fetchImpl.mock.calls.length).toBe(2);
  });

  it('without a host policy: reads allowed, no writes', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl);
    expect((await g.callTool('list_organizations', {})).isError).toBeUndefined();
    const write = await g.callTool('set_update_approvals', CALLS.set_update_approvals![0]!);
    expect(write.content[0]!.text).toMatch(/writes are disabled/);
    expect(fetchImpl.mock.calls.some(([url]) => String(url).endsWith('/approvals'))).toBe(false);
  });

  it('leaves out and refuses the tools the host disables, and refuses an unknown tool in the policy', async () => {
    const g = gateway(action1(), { policy: { disabledTools: ['get_report_data', 'action1_list_reports'] } });
    expect(g.tools.map(tool => tool.name)).not.toContain('get_report_data');
    expect(g.tools.map(tool => tool.name)).not.toContain('list_reports');
    expect((await g.callTool('get_report_data', { orgId: 'org-1', reportId: 'rep-1' })).content[0]!.text).toMatch(/disabled/);
    const search = await g.callTool('search_capabilities', { query: 'report' });
    expect(JSON.stringify(search.structuredContent)).not.toContain('get_report_data');
    expect(() => gateway(action1(), { policy: { disabledTools: ['run_script'] } })).toThrow(/not a known gateway tool/);
  });

  it('audits to the host’s sink only, with the caller as a pseudonym, and does not run a tool whose start record fails', async () => {
    const records = sink();
    await gateway(action1(), { policy: { audit: records.audit } }).callTool('list_endpoints', { orgId: 'org-1' }, { caller: 'mette@example.com' });
    expect(records.records.map(record => record.action)).toEqual(['start', 'finish']);
    expect(records.records[0]!.caller).toBe(callerPseudonym('mette@example.com'));
    expect(JSON.stringify(records.records)).not.toContain('mette');
    expect(JSON.stringify(records.records)).not.toContain('org-1');

    const fetchImpl = action1();
    const failing = await gateway(fetchImpl, {
      policy: {
        audit: () => {
          throw new Error('sink down');
        },
      },
    }).callTool('list_organizations', {});
    expect(failing.isError).toBe(true);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('Action1 gateway tenants', () => {
  it('keeps two tenants apart when they call at the same time, each with its own credentials and sink', async () => {
    const a = sink();
    const b = sink();
    const fetchA = action1();
    const fetchB = action1();
    const ga = gateway(fetchA, { policy: { audit: a.audit } });
    const gb = createAction1Gateway({ clientId: 'test-client-0002@action1.com', clientSecret: SECRET_B, region: 'uk', fetchImpl: fetchB, policy: { audit: b.audit } });
    await Promise.all([ga.callTool('list_organizations', {}), gb.callTool('list_organizations', {}), ga.callTool('check_connection', {})]);
    expect(JSON.stringify(fetchA.mock.calls)).not.toContain(SECRET_B);
    expect(JSON.stringify(fetchB.mock.calls)).not.toContain(SECRET_A);
    expect(a.records).toHaveLength(4);
    expect(b.records).toHaveLength(2);
  });

  it('runs a call made from inside another instance’s sink under its own scope', async () => {
    const inner = gateway(action1());
    let innerResult: unknown;
    const outer = gateway(action1(), {
      policy: {
        enableWrites: true,
        audit: async () => {
          innerResult ??= await inner.callTool('set_update_approvals', CALLS.set_update_approvals![0]!);
        },
      },
    });
    await outer.callTool('list_organizations', {});
    expect(JSON.stringify(innerResult)).toMatch(/writes are disabled/);
  });
});
