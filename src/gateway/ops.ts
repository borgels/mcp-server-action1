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
