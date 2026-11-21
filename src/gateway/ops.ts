import { cveSegment, idSegment, type Action1GatewayClient, type QueryValue } from './client.js';

/**
 * The narrow operations of the embedded gateway (src/gateway/tools.ts).
 *
 * Every answer is projected onto an allowlist of fields before it leaves: a
 * field that is not named here is never passed on. So an endpoint's IP and MAC
 * addresses, serial number, directory groups and custom attributes are never
 * returned, nor the e-mail of whoever recorded a remediation, nor anything
 * Action1 adds later. Report rows keep only the columns named in
 * REPORT_COLUMNS, as plain values. A user name or report value that looks like
 * a mail, IP or MAC address is left out wherever it appears.
 */

type Json = Record<string, unknown>;
type Projection = Record<string, (value: unknown) => unknown>;

/** Largest page a gateway list asks for. */
export const GATEWAY_MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

function asObject(value: unknown): Json | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Json) : undefined;
}

/** A string, number, boolean or null as it is; anything else is dropped. */
function plain(value: unknown): unknown {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value) ? value : undefined;
}

/** Only the named fields of `source`, each through its projection; fields that come out undefined are left out. */
function pick(source: Json, projection: Projection): Json {
  const out: Json = {};
  for (const [field, project] of Object.entries(projection)) {
    if (!Object.hasOwn(source, field)) continue;
    const value = project(source[field]);
    if (value !== undefined) out[field] = value;
  }
  return out;
}

function projector(projection: Projection): (value: unknown) => Json {
  return value => pick(asObject(value) ?? {}, projection);
}

function listOf(project: (value: unknown) => unknown): (value: unknown) => unknown {
  return value => (Array.isArray(value) ? value.map(project) : undefined);
}

const COUNTS = projector({ critical: plain, other: plain });

const ORGANIZATION = projector({ id: plain, name: plain, description: plain });

const ENDPOINT_FIELDS: Projection = {
  id: plain,
  name: plain,
  device_name: plain,
  OS: plain,
  platform: plain,
  architecture: plain,
  manufacturer: plain,
  CPU_name: plain,
  RAM: plain,
  disk: plain,
  status: plain,
  online_status: plain,
  last_seen: plain,
  last_boot_time: plain,
  reboot_required: plain,
  update_status: plain,
  vulnerability_status: plain,
  missing_updates: COUNTS,
  vulnerabilities: COUNTS,
  agent_version: plain,
  subscription_status: plain,
  // The logged-in user name, but never when it is a mail address.
  user: safe,
  organization_id: plain,
};
const ENDPOINT = projector(ENDPOINT_FIELDS);
const GROUP_MEMBER = projector({ ...ENDPOINT_FIELDS, added_via: plain });
const GROUP = projector({ id: plain, name: plain, description: plain });

const UPDATE_VERSION = projector({
  id: plain,
  version: plain,
  release_date: plain,
  security_severity: plain,
  update_type: plain,
  approval_status: plain,
  update_sla_deadline: plain,
  update_sla_status: plain,
  security_CVE: plain,
  status: plain,
});
const UPDATE = projector({
  id: plain,
  name: plain,
  vendor: plain,
  update_type: plain,
  kb_number: plain,
  reboot_needed: plain,
  optional: plain,
  recommended: plain,
  size: plain,
  builtin: plain,
  versions: listOf(UPDATE_VERSION),
});

const SOFTWARE = projector({
  product_name: plain,
  platform: plain,
  endpoints_count: plain,
  versions: listOf(projector({ version: plain })),
});
const VULNERABILITY = projector({
  cve_id: plain,
  cvss_score: plain,
  base_severity: plain,
  published_date: plain,
  description: plain,
  remediation_status: plain,
  remediation_deadline: plain,
  endpoints_count: plain,
  cisa_kev: plain,
  organization_id: plain,
  software: listOf(SOFTWARE),
});
const VULNERABLE_ENDPOINT = projector({
  endpoint_id: plain,
  endpoint_name: plain,
  OS: plain,
  user: safe,
  organization_id: plain,
  software: listOf(SOFTWARE),
});
const REMEDIATION = projector({
  remediation_id: plain,
  product_name: plain,
  comment: plain,
  creation_date: plain,
  remediated_by: projector({ display_name: plain }),
});

const INSTALLED_FIELDS = new Set(['Name', 'Vendor', 'Version', 'Platform', 'Endpoints', 'Update Status', 'Install Type', 'Install Date']);
const INSTALLED_SOFTWARE = projector({
  id: plain,
  fields: value => {
    const fields = asObject(value);
    if (!fields) return undefined;
    return Object.fromEntries(Object.entries(fields).filter(([key, entry]) => INSTALLED_FIELDS.has(key) && plain(entry) !== undefined));
  },
});

const REPORT = projector({ id: plain, name: plain, description: plain, long_description: plain, builtin: plain, simple: plain });

/**
 * Report columns that are passed on, by name (compared without case, spaces, `_` or `-`): the inventory, update and
 * vulnerability columns of Action1's reports. Any other column is left out, whatever it holds.
 */
const REPORT_COLUMNS = new Set(
  [
    'Name', 'Endpoint', 'Endpoint Name', 'Device Name', 'Computer', 'OS', 'Operating System', 'Platform', 'Architecture',
    'Manufacturer', 'Model', 'Vendor', 'Product', 'Product Name', 'Software', 'Version', 'Installed Version',
    'Latest Version', 'Update', 'Update Name', 'Updates', 'KB', 'KB Number', 'Title', 'Category', 'Type', 'Update Type',
    'Severity', 'Security Severity', 'Approval Status', 'Release Date', 'Status', 'Update Status', 'Online Status',
    'Reboot Required', 'Last Seen', 'Last Boot Time', 'Last Update', 'Missing Updates', 'Missing Critical Updates',
    'Missing Other Updates', 'Endpoints', 'Endpoints Count', 'Count', 'Total', 'CVE', 'CVE ID', 'CVSS', 'CVSS Score',
    'Score', 'Vulnerabilities', 'Remediation Status', 'Remediation Deadline', 'CISA KEV', 'Organization', 'Group',
    'Agent Version', 'Disk', 'Free Space', 'RAM', 'CPU', 'Warranty', 'Install Date',
  ].map(column => column.toLowerCase().replace(/[\s_-]/g, '')),
);

/** A value that looks like a mail address, an IP or MAC address: never passed on, whatever its field. */
/** A mail address (any text with an @), an IP or MAC address. */
const MAIL = /@/;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const MAC_OR_IPV6 = /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}|[0-9a-f]{0,4}::[0-9a-f]{0,4}/i;

/** A plain value, unless it looks like a mail, IP or MAC address. */
function safe(value: unknown): unknown {
  const kept = plain(value);
  return typeof kept === 'string' && (MAIL.test(kept) || IPV4.test(kept) || MAC_OR_IPV6.test(kept)) ? undefined : kept;
}

/** A version: four numbers have the shape of an IP address and are kept, but never a mail or MAC address. */
function safeVersion(value: unknown): unknown {
  const kept = plain(value);
  return typeof kept === 'string' && (MAIL.test(kept) || MAC_OR_IPV6.test(kept)) ? undefined : kept;
}

const REPORT_ROW = projector({
  id: plain,
  fields: value => {
    const fields = asObject(value);
    if (!fields) return undefined;
    return Object.fromEntries(
      Object.entries(fields).filter(
        ([key, entry]) => {
          const column = key.toLowerCase().replace(/[\s_-]/g, '');
          const kept = column.includes('version') ? safeVersion(entry) : safe(entry);
          return REPORT_COLUMNS.has(column) && kept !== undefined;
        },
      ),
    );
  },
});

interface ResultPage {
  items?: unknown;
  total_items?: unknown;
}

function pageQuery(input: { limit?: number; from?: number; search?: string }): Record<string, QueryValue> {
  return {
    limit: Math.min(input.limit ?? DEFAULT_LIMIT, GATEWAY_MAX_LIMIT),
    from: input.from ?? 0,
    filter: input.search,
  };
}

/** A result page as the gateway returns it: the projected items, the total and the offset of the next page. */
function page(raw: unknown, from: number, project: (value: unknown) => unknown): Json {
  const result = (asObject(raw) ?? {}) as ResultPage;
  const items = Array.isArray(result.items) ? result.items.map(project) : [];
  const total = typeof result.total_items === 'number' ? result.total_items : Number(result.total_items);
  const out: Json = { items, from };
  if (Number.isFinite(total)) {
    out.total = total;
    if (from + items.length < total) out.nextFrom = from + items.length;
  }
  return out;
}

async function listPage(
  client: Action1GatewayClient,
  path: string,
  input: { limit?: number; from?: number; search?: string },
  project: (value: unknown) => unknown,
  extra: Record<string, QueryValue> = {},
): Promise<Json> {
  const from = input.from ?? 0;
  return page(await client.get(path, { ...pageQuery(input), ...extra }), from, project);
}

const org = (orgId: string) => idSegment(orgId, 'orgId');

export async function checkConnection(client: Action1GatewayClient): Promise<Json> {
  const result = (asObject(await client.get('/organizations', { limit: 1, from: 0 })) ?? {}) as ResultPage;
  const total = typeof result.total_items === 'number' ? result.total_items : Number(result.total_items);
  return { connected: true, organizations: Number.isFinite(total) ? total : Array.isArray(result.items) ? result.items.length : 0 };
}

export interface PageInput {
  limit?: number;
  from?: number;
  search?: string;
}

export function listOrganizations(client: Action1GatewayClient, input: PageInput): Promise<Json> {
  return listPage(client, '/organizations', input, ORGANIZATION);
}

export function listEndpoints(
  client: Action1GatewayClient,
  input: PageInput & {
    orgId: string;
    status?: string;
    onlineStatus?: string;
    updateStatus?: string;
    vulnerabilityStatus?: string;
    rebootRequired?: string;
  },
): Promise<Json> {
  return listPage(client, `/endpoints/managed/${org(input.orgId)}`, input, ENDPOINT, {
    status: input.status,
    online_status: input.onlineStatus,
    update_status: input.updateStatus,
    vulnerability_status: input.vulnerabilityStatus,
    reboot_required: input.rebootRequired,
  });
}

export async function getEndpoint(
  client: Action1GatewayClient,
  input: { orgId: string; endpointId: string; includeMissingUpdates?: boolean },
): Promise<Json> {
  const base = `/endpoints/managed/${org(input.orgId)}/${idSegment(input.endpointId, 'endpointId')}`;
  const endpoint = ENDPOINT(await client.get(base));
  if (!input.includeMissingUpdates) return endpoint;
  const missing = await listPage(client, `${base}/missing-updates`, { limit: GATEWAY_MAX_LIMIT }, UPDATE);
  return { ...endpoint, missingUpdates: missing };
}

export async function listEndpointGroups(
  client: Action1GatewayClient,
  input: PageInput & { orgId: string; groupId?: string; members?: boolean },
): Promise<Json> {
  const base = `/endpoints/groups/${org(input.orgId)}`;
  if (input.groupId) {
    const groupPath = `${base}/${idSegment(input.groupId, 'groupId')}`;
    return input.members ? listPage(client, `${groupPath}/contents`, input, GROUP_MEMBER) : GROUP(await client.get(groupPath));
  }
  return listPage(client, base, input, GROUP);
}

export async function listUpdates(
  client: Action1GatewayClient,
  input: PageInput & {
    orgId: string;
    packageId?: string;
    approvalStatus?: string;
    securitySeverity?: string;
    onlyLatest?: boolean;
  },
): Promise<Json> {
  const extra = {
    approval_status: input.approvalStatus,
    security_severity: input.securitySeverity,
    only_latest: input.onlyLatest === undefined ? undefined : input.onlyLatest ? 'Yes' : 'No',
  };
  if (input.packageId) {
    const raw = await client.get(`/updates/${org(input.orgId)}/${idSegment(input.packageId, 'packageId')}`, {
      ...pageQuery(input),
      ...extra,
    });
    return Array.isArray(asObject(raw)?.items) ? page(raw, input.from ?? 0, UPDATE) : UPDATE(raw);
  }
  return listPage(client, `/updates/${org(input.orgId)}`, input, UPDATE, extra);
}

export async function listVulnerabilities(
  client: Action1GatewayClient,
  input: PageInput & {
    orgId: string;
    cveId?: string;
    detail?: 'endpoints' | 'remediations';
    score?: string;
    remediationStatus?: string;
    endpointId?: string;
  },
): Promise<Json> {
  const base = `/vulnerabilities/${org(input.orgId)}`;
  if (input.cveId) {
    const cvePath = `${base}/${cveSegment(input.cveId)}`;
    if (input.detail === 'endpoints') return listPage(client, `${cvePath}/endpoints`, input, VULNERABLE_ENDPOINT);
    if (input.detail === 'remediations') return listPage(client, `${cvePath}/remediations`, input, REMEDIATION);
    return VULNERABILITY(await client.get(cvePath));
  }
  if (input.detail) throw new Error('Give cveId with detail.');
  return listPage(client, base, input, VULNERABILITY, {
    score: input.score,
    remediation_status: input.remediationStatus,
    endpoint_id: input.endpointId === undefined ? undefined : idSegment(input.endpointId, 'endpointId'),
  });
}

export function getInstalledSoftware(
  client: Action1GatewayClient,
  input: PageInput & { orgId: string; endpointId?: string },
): Promise<Json> {
  const base = `/installed-software/${org(input.orgId)}/data`;
  const path = input.endpointId ? `${base}/${idSegment(input.endpointId, 'endpointId')}` : base;
  return listPage(client, path, input, INSTALLED_SOFTWARE);
}

export function listReports(client: Action1GatewayClient, input: PageInput): Promise<Json> {
  return listPage(client, '/reports/all', input, REPORT);
}

export function getReportData(client: Action1GatewayClient, input: PageInput & { orgId: string; reportId: string }): Promise<Json> {
  return listPage(client, `/reportdata/${org(input.orgId)}/${idSegment(input.reportId, 'reportId')}/data`, input, REPORT_ROW);
}

export async function setUpdateApprovals(
  client: Action1GatewayClient,
  input: { orgId: string; approvalStatus: 'Approved' | 'Declined' | 'New'; packages: Array<{ packageId: string; versionId: string }> },
): Promise<Json> {
  if (input.orgId.toLowerCase() === 'all') {
    throw new Error('Give one organization: approvals for all organizations at once are refused.');
  }
  const packages = input.packages.map(entry => ({
    packages_id: decodeURIComponent(idSegment(entry.packageId, 'packageId')),
    version_id: decodeURIComponent(idSegment(entry.versionId, 'versionId')),
  }));
  const raw = await client.post(`/updates/${org(input.orgId)}/approvals`, [{ approval_status: input.approvalStatus, packages }]);
  const details = asObject(raw)?.details;
  return {
    approvalStatus: input.approvalStatus,
    packages: Array.isArray(details)
      ? details.map(projector({ packages_id: plain, version_id: plain }))
      : packages,
  };
}

// --- Everyday IT work: automations, the software repository and deployments ---

/** The targets of an automation, as ids and types only: never filters or the names Action1 resolves them to. */
const TARGET = projector({ id: plain, type: plain });
/** An action of an automation: its name and template only. The parameters (script text included) are never returned. */
const ACTION = projector({ name: plain, template_id: plain });
const AUTOMATION = projector({
  id: plain,
  name: plain,
  status: plain,
  settings: plain,
  retry_minutes: plain,
  last_run: plain,
  next_run: plain,
  start_time: plain,
  end_time: plain,
  endpoints: listOf(TARGET),
  actions: listOf(ACTION),
});
const AUTOMATION_RESULT = projector({
  endpoint_id: plain,
  endpoint_name: plain,
  status: plain,
  start_time: plain,
  end_time: plain,
});
const REPOSITORY_VERSION = projector({
  id: plain,
  version: plain,
  release_date: plain,
  status: plain,
  platform: plain,
  architecture: plain,
});
const REPOSITORY_PACKAGE = projector({
  id: plain,
  name: plain,
  vendor: plain,
  description: plain,
  platform: plain,
  builtin: plain,
  versions: listOf(REPOSITORY_VERSION),
});

export async function listAutomations(
  client: Action1GatewayClient,
  input: PageInput & { orgId: string; kind: 'schedules' | 'instances'; automationId?: string; endpointResults?: boolean },
): Promise<Json> {
  const base = `/automations/${input.kind}/${org(input.orgId)}`;
  if (input.automationId) {
    const itemPath = `${base}/${idSegment(input.automationId, 'automationId')}`;
    if (input.endpointResults) {
      if (input.kind !== 'instances') throw new Error('endpointResults needs kind "instances".');
      return listPage(client, `${itemPath}/endpoint-results`, input, AUTOMATION_RESULT);
    }
    return AUTOMATION(await client.get(itemPath));
  }
  if (input.endpointResults) throw new Error('Give automationId with endpointResults.');
  return listPage(client, base, input, AUTOMATION);
}

export async function listSoftwareRepository(
  client: Action1GatewayClient,
  input: PageInput & { orgId: string; packageId?: string },
): Promise<Json> {
  const base = `/software-repository/${org(input.orgId)}`;
  if (input.packageId) return REPOSITORY_PACKAGE(await client.get(`${base}/${idSegment(input.packageId, 'packageId')}`));
  return listPage(client, base, input, REPOSITORY_PACKAGE);
}

export interface TargetInput {
  type: 'endpoint' | 'group';
  id: string;
}

export interface PackageInput {
  packageId: string;
  version: string;
}

/** Most computers and groups one run may name. */
export const MAX_TARGETS = 50;

/** One organization, never "all": a run or deployment always belongs to one organization. */
function oneOrg(orgId: string): string {
  if (orgId.trim().toLowerCase() === 'all') {
    throw new Error('Give one organization: a run for all organizations at once is refused.');
  }
  return org(orgId);
}

/**
 * The computers and groups a run is for, named one by one. "All" (the name Action1 gives every computer) is refused as
 * an id, so a run made here always names its targets.
 */
function targets(list: readonly TargetInput[]): Array<{ id: string; type: 'Endpoint' | 'EndpointGroup' }> {
  if (list.length === 0 || list.length > MAX_TARGETS) throw new Error(`Name between 1 and ${MAX_TARGETS} computers or groups.`);
  const seen = new Set<string>();
  return list.map(target => {
    if (target.id.trim().toLowerCase() === 'all') {
      throw new Error('Name the computers or groups: "all" is refused as a target.');
    }
    const id = decodeURIComponent(idSegment(target.id, target.type === 'group' ? 'groupId' : 'endpointId'));
    const key = `${target.type}:${id}`;
    if (seen.has(key)) throw new Error('Each computer or group may be named once.');
    seen.add(key);
    return { id, type: target.type === 'group' ? 'EndpointGroup' : 'Endpoint' };
  });
}

/**
 * The targets of an automation as an administrator set them up, held to the same rules as named targets: each a
 * computer or group by a valid id, at most MAX_TARGETS, none twice, and never "all". An automation set up for every
 * computer, for more than MAX_TARGETS, or with targets of another kind (filters) is not run on its own targets: the
 * targets must then be named.
 */
function ownTargets(value: unknown): Array<{ id: string; type: 'Endpoint' | 'EndpointGroup' }> {
  const list = Array.isArray(value) ? value : [];
  const named: TargetInput[] = list.map(entry => {
    const target = asObject(entry);
    const type = target?.type === 'Endpoint' ? 'endpoint' : target?.type === 'EndpointGroup' ? 'group' : undefined;
    if (!target || type === undefined || typeof target.id !== 'string') {
      throw new Error('The automation has targets that are not computers or groups; name them in targets.');
    }
    return { type, id: target.id };
  });
  if (named.length === 0) throw new Error('The automation has no computers or groups; name them in targets.');
  if (named.some(target => target.id.trim().toLowerCase() === 'all')) {
    throw new Error('The automation is set up for every computer; name the computers or groups in targets.');
  }
  if (named.length > MAX_TARGETS) throw new Error(`The automation has more than ${MAX_TARGETS} targets; name them in targets.`);
  return targets(named);
}

/** Packages as Action1 takes them in a deployment: one object per package, its id mapped to the version. */
function packageMap(list: readonly PackageInput[]): Array<Record<string, string>> {
  const seen = new Set<string>();
  return list.map(entry => {
    const id = decodeURIComponent(idSegment(entry.packageId, 'packageId'));
    if (seen.has(id)) throw new Error('Each package may be named once.');
    seen.add(id);
    return { [id]: entry.version };
  });
}

/** The run Action1 started, by id, name and status only. */
const RUN = projector({ id: plain, name: plain, status: plain });

/** UTC to the minute, in the name of a run: two runs on the same day can be told apart in Action1. */
function stamp(): string {
  return new Date().toISOString().slice(0, 16).replace('T', ' ');
}

const REBOOT_NO = { auto_reboot: 'no' };
/** Action1's own text for the warning before a restart; the host may give its own (rebootMessage). */
export const DEFAULT_REBOOT_MESSAGE =
  'Your computer requires maintenance and will be rebooted. Please save all work and reboot now to avoid losing any data.';
/** Action1's own reboot settings for an update deployment that may restart: the user is warned and has four hours. */
function rebootWithWarning(message: string | undefined) {
  return { auto_reboot: 'yes', show_message: 'yes', message_text: message ?? DEFAULT_REBOOT_MESSAGE, timeout: 240 };
}

export async function deployUpdates(
  client: Action1GatewayClient,
  input: { orgId: string; targets: TargetInput[]; packages: PackageInput[]; allowReboot?: boolean },
): Promise<Json> {
  const path = `/automations/instances/${oneOrg(input.orgId)}`;
  const endpoints = targets(input.targets);
  const packages = packageMap(input.packages);
  const raw = await client.post(path, {
    name: `Deploy updates ${stamp()}`,
    retry_minutes: '1440',
    endpoints,
    actions: [
      {
        name: 'Deploy Update',
        template_id: 'deploy_update',
        params: {
          display_summary: 'Updates deployed through the gateway.',
          packages,
          update_approval: 'manual',
          scope: 'Specified',
          reboot_options: input.allowReboot ? rebootWithWarning(client.rebootMessage) : REBOOT_NO,
        },
      },
    ],
  });
  return { ...RUN(raw), targets: endpoints.length, packages: packages.length, allowReboot: input.allowReboot === true };
}

export async function deploySoftware(
  client: Action1GatewayClient,
  input: { orgId: string; targets: TargetInput[]; packages: PackageInput[] },
): Promise<Json> {
  const path = `/automations/instances/${oneOrg(input.orgId)}`;
  const endpoints = targets(input.targets);
  const packages = packageMap(input.packages);
  const raw = await client.post(path, {
    name: `Deploy software ${stamp()}`,
    retry_minutes: '1440',
    endpoints,
    actions: [
      {
        name: 'Deploy Software',
        template_id: 'deploy_package',
        params: {
          display_summary: 'Software deployed through the gateway.',
          packages,
          reboot_options: REBOOT_NO,
        },
      },
    ],
  });
  return { ...RUN(raw), targets: endpoints.length, packages: packages.length };
}

/**
 * Runs an automation an Action1 administrator has already set up, now, as a new run with the automation's own actions.
 * The actions go back to Action1 exactly as Action1 gave them and are never returned; nothing here writes a script or
 * an action. The run is for the computers and groups named in `targets`, or, without them, for the automation's own.
 */
export async function runAutomation(
  client: Action1GatewayClient,
  input: { orgId: string; automationId: string; targets?: TargetInput[] },
): Promise<Json> {
  const orgSegment = oneOrg(input.orgId);
  const chosen = input.targets === undefined ? undefined : targets(input.targets);
  const schedule = asObject(await client.get(`/automations/schedules/${orgSegment}/${idSegment(input.automationId, 'automationId')}`));
  const actions = schedule?.actions;
  if (!schedule || !Array.isArray(actions) || actions.length === 0) {
    throw new Error('The automation has no actions to run.');
  }
  const own = chosen === undefined ? ownTargets(schedule.endpoints) : [];
  const endpoints = chosen ?? own;
  const name = typeof schedule.name === 'string' && schedule.name.trim() !== '' ? schedule.name.slice(0, 150) : 'Automation';
  const retry = schedule.retry_minutes;
  const raw = await client.post(`/automations/instances/${orgSegment}`, {
    name: `${name} (run now ${stamp()})`,
    retry_minutes: typeof retry === 'string' || typeof retry === 'number' ? String(retry) : '1440',
    endpoints,
    actions,
  });
  return {
    ...RUN(raw),
    automationId: input.automationId,
    actions: actions.map(ACTION),
    ...(chosen ? { targets: chosen.length } : { targets: 'automation', automationTargets: own.length }),
  };
}
