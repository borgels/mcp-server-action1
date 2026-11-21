import { describe, expect, it, vi } from 'vitest';
import { createAction1Gateway, type GatewayJsonObject } from '../src/gateway.js';

const CLIENT_ID = 'test-client-0001@action1.com';
const SECRET = 'qqqqwwwwzzzzxxxx1';
const ACCESS_TOKEN = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ0ZXN0In0', 'c2lnbmF0dXJlLXBhcnQ'].join('.');
const SCRIPT = 'Remove-Item C:\\temp\\* -Recurse';

const SCHEDULE = {
  id: 'auto-1',
  name: 'Weekly cleanup',
  retry_minutes: '480',
  endpoints: [{ id: 'g-1', type: 'EndpointGroup' }],
  actions: [{ id: 'Run_Command_1', name: 'Run Command', template_id: 'run_script', params: { script_text: SCRIPT } }],
};

function json(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function action1(overrides: Record<string, () => Response> = {}) {
  return vi.fn<typeof fetch>(async (url, init) => {
    const path = new URL(String(url)).pathname.replace(/^\/api\/3\.0/, '');
    const key = `${init?.method ?? 'GET'} ${path}`;
    if (overrides[key]) return overrides[key]();
    if (key === 'POST /oauth2/token') return json({ access_token: ACCESS_TOKEN, expires_in: 3600 });
    if (key === 'GET /automations/schedules/org-1') return json({ total_items: 1, items: [SCHEDULE] });
    if (key === 'GET /automations/schedules/org-1/auto-1') return json(SCHEDULE);
    if (key === 'GET /automations/instances/org-1/run-1/endpoint-results')
      return json({ total_items: 1, items: [{ endpoint_id: 'ep-1', endpoint_name: 'Laptop 7', status: 'Success', output: 'secret output' }] });
    if (key === 'POST /automations/instances/org-1') return json({ id: 'run-2', name: 'started', status: 'Running' });
    return json({}, 404);
  });
}

function gateway(fetchImpl: typeof fetch, enableWrites = true) {
  return createAction1Gateway({ clientId: CLIENT_ID, clientSecret: SECRET, region: 'eu', fetchImpl, policy: { enableWrites } });
}

function posted(fetchImpl: ReturnType<typeof action1>): unknown[] {
  return fetchImpl.mock.calls
    .filter(([url, init]) => init?.method === 'POST' && !String(url).endsWith('/oauth2/token'))
    .map(([, init]) => JSON.parse(String(init?.body)) as unknown);
}

describe('Action1 gateway everyday work', () => {
  it('lists automations without their action parameters, and run results without output', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl);
    const list = await g.callTool('list_automations', { orgId: 'org-1', kind: 'schedules' });
    expect(JSON.stringify(list)).not.toContain('Remove-Item');
    expect(list.structuredContent).toMatchObject({ items: [{ id: 'auto-1', actions: [{ name: 'Run Command', template_id: 'run_script' }] }] });
    const results = await g.callTool('list_automations', { orgId: 'org-1', kind: 'instances', automationId: 'run-1', endpointResults: true });
    expect(JSON.stringify(results)).not.toContain('secret output');
    const wrong = await g.callTool('list_automations', { orgId: 'org-1', kind: 'schedules', automationId: 'auto-1', endpointResults: true });
    expect(wrong.isError).toBe(true);
  });

  it('deploys updates to the named computers without a restart unless asked', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl);
    const result = await g.callTool('deploy_updates', {
      orgId: 'org-1',
      targets: [{ type: 'endpoint', id: 'ep-1' }, { type: 'group', id: 'g-1' }],
      packages: [{ packageId: 'pkg-1', version: '1.2.3' }],
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ id: 'run-2', status: 'Running', targets: 2, packages: 1, allowReboot: false });
    const [body] = posted(fetchImpl) as Array<Record<string, any>>;
    expect(body!.endpoints).toEqual([{ id: 'ep-1', type: 'Endpoint' }, { id: 'g-1', type: 'EndpointGroup' }]);
    expect(body!.actions[0].template_id).toBe('deploy_update');
    expect(body!.actions[0].params.packages).toEqual([{ 'pkg-1': '1.2.3' }]);
    expect(body!.actions[0].params.reboot_options).toEqual({ auto_reboot: 'no' });

    await g.callTool('deploy_updates', { orgId: 'org-1', targets: [{ type: 'endpoint', id: 'ep-1' }], packages: [{ packageId: 'pkg-1', version: '1.2.3' }], allowReboot: true });
    const second = posted(fetchImpl)[1] as Record<string, any>;
    expect(second.actions[0].params.reboot_options).toMatchObject({ auto_reboot: 'yes', show_message: 'yes', timeout: 240 });
  });

  it('deploys a repository package without a restart', async () => {
    const fetchImpl = action1();
    const result = await gateway(fetchImpl).callTool('deploy_software', {
      orgId: 'org-1',
      targets: [{ type: 'group', id: 'g-1' }],
      packages: [{ packageId: 'sw-1', version: '2.0' }],
    });
    expect(result.isError).toBeUndefined();
    const [body] = posted(fetchImpl) as Array<Record<string, any>>;
    expect(body!.actions[0]).toMatchObject({ template_id: 'deploy_package', params: { packages: [{ 'sw-1': '2.0' }], reboot_options: { auto_reboot: 'no' } } });
  });

  it('runs an automation with its own actions, which are sent back to Action1 but never returned', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl);
    const own = await g.callTool('run_automation', { orgId: 'org-1', automationId: 'auto-1' });
    expect(own.isError).toBeUndefined();
    expect(JSON.stringify(own)).not.toContain('Remove-Item');
    expect(own.structuredContent).toMatchObject({ id: 'run-2', targets: 'automation', automationTargets: 1, actions: [{ template_id: 'run_script' }] });
    const [body] = posted(fetchImpl) as Array<Record<string, any>>;
    expect(body!.actions).toEqual(SCHEDULE.actions);
    expect(body!.endpoints).toEqual(SCHEDULE.endpoints);
    expect(body!.retry_minutes).toBe('480');
    expect(body!.name).toMatch(/^Weekly cleanup \(run now /);

    const narrowed = await g.callTool('run_automation', { orgId: 'org-1', automationId: 'auto-1', targets: [{ type: 'endpoint', id: 'ep-9' }] });
    expect(narrowed.structuredContent).toMatchObject({ targets: 1 });
    expect((posted(fetchImpl)[1] as Record<string, any>).endpoints).toEqual([{ id: 'ep-9', type: 'Endpoint' }]);
  });

  it('refuses "all", duplicates, too many targets and empty automations before anything is sent', async () => {
    const fetchImpl = action1({ 'GET /automations/schedules/org-1/auto-2': () => json({ id: 'auto-2', actions: [] }) });
    const g = gateway(fetchImpl);
    const pkg = [{ packageId: 'pkg-1', version: '1' }];
    const refused: Array<[string, GatewayJsonObject]> = [
      ['deploy_updates', { orgId: 'all', targets: [{ type: 'endpoint', id: 'ep-1' }], packages: pkg }],
      ['deploy_updates', { orgId: 'org-1', targets: [{ type: 'group', id: 'ALL' }], packages: pkg }],
      ['deploy_updates', { orgId: 'org-1', targets: [{ type: 'endpoint', id: 'ep-1' }, { type: 'endpoint', id: 'ep-1' }], packages: pkg }],
      ['deploy_updates', { orgId: 'org-1', targets: [], packages: pkg }],
      ['deploy_updates', { orgId: 'org-1', targets: Array.from({ length: 51 }, (_, i) => ({ type: 'endpoint', id: `ep-${i}` })), packages: pkg }],
      ['deploy_software', { orgId: 'org-1', targets: [{ type: 'endpoint', id: 'ep-1' }], packages: [...pkg, ...pkg] }],
      ['deploy_software', { orgId: 'org-1', targets: [{ type: 'endpoint', id: '../x' }], packages: pkg }],
      ['run_automation', { orgId: 'all', automationId: 'auto-1' }],
      ['run_automation', { orgId: 'org-1', automationId: 'auto-1', targets: [{ type: 'group', id: 'all' }] }],
    ];
    for (const [tool, input] of refused) {
      expect((await g.callTool(tool, input)).isError, `${tool} ${JSON.stringify(input).slice(0, 80)}`).toBe(true);
    }
    expect(posted(fetchImpl)).toEqual([]);
    expect((await g.callTool('run_automation', { orgId: 'org-1', automationId: 'auto-2' })).isError).toBe(true);
    expect(posted(fetchImpl)).toEqual([]);
  });

  it('runs no change unless the host enables writes', async () => {
    const fetchImpl = action1();
    const g = gateway(fetchImpl, false);
    for (const [tool, input] of [
      ['run_automation', { orgId: 'org-1', automationId: 'auto-1' }],
      ['deploy_software', { orgId: 'org-1', targets: [{ type: 'group', id: 'g-1' }], packages: [{ packageId: 'sw-1', version: '2.0' }] }],
    ] as Array<[string, GatewayJsonObject]>) {
      const result = await g.callTool(tool, input);
      expect(result.isError).toBe(true);
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('Action1 gateway failure metadata', () => {
  it('gives the HTTP status and a request id in form on an error result, and nothing else', async () => {
    const fetchImpl = action1({
      'POST /automations/instances/org-1': () => json({ developer_message: 'nope' }, 403, { 'x-request-id': '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b' }),
      'GET /automations/schedules/org-1': () => json({}, 500, { 'x-request-id': 'not an id, a sentence' }),
    });
    const g = gateway(fetchImpl);
    const denied = await g.callTool('deploy_software', { orgId: 'org-1', targets: [{ type: 'group', id: 'g-1' }], packages: [{ packageId: 'sw-1', version: '2.0' }] });
    expect(denied.isError).toBe(true);
    expect(denied.failure).toEqual({ httpStatus: 403, requestId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b' });
    expect(JSON.stringify(denied)).not.toContain('nope');
    const broken = await g.callTool('list_automations', { orgId: 'org-1', kind: 'schedules' });
    expect(broken.failure).toEqual({ httpStatus: 500 });
    const invalid = await g.callTool('list_automations', { orgId: 'org-1' });
    expect(invalid.failure).toBeUndefined();
    const ok = await g.callTool('run_automation', { orgId: 'org-1', automationId: 'auto-1' });
    expect(ok.failure).toEqual({ httpStatus: 403, requestId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b' });
  });

  it('gives the status of a refused redirect, and of a refused token request', async () => {
    const redirect = action1({ 'GET /automations/schedules/org-1': () => new Response(null, { status: 302, headers: { location: 'https://elsewhere.example.org/' } }) });
    const moved = await gateway(redirect).callTool('list_automations', { orgId: 'org-1', kind: 'schedules' });
    expect(moved.failure).toEqual({ httpStatus: 302 });
    expect(JSON.stringify(moved)).not.toContain('elsewhere');
    const token = action1({ 'POST /oauth2/token': () => json({}, 401, { 'request-id': 'abcdef01ab23cd45' }) });
    const refused = await gateway(token).callTool('list_automations', { orgId: 'org-1', kind: 'schedules' });
    expect(refused.failure).toEqual({ httpStatus: 401, requestId: 'abcdef01ab23cd45' });
  });
});
