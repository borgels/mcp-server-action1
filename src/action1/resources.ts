import type { Action1Client, QueryValue } from './client.js';
import { assertWritesEnabled } from './policy.js';

/**
 * Action1 list responses are ResultPage objects:
 * { items[], total_items, limit, next_page, prev_page }.
 * Pagination is offset-based via limit + from; we compute the next offset
 * ourselves instead of parsing the next_page URL.
 */
export interface PageInput {
  limit?: number;
  from?: number;
  sortby?: string;
  filter?: string;
}

const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 500;

function pageQuery(input: PageInput): Record<string, QueryValue> {
  return {
    limit: Math.min(input.limit ?? DEFAULT_LIMIT, MAX_LIMIT),
    from: input.from ?? 0,
    sortby: input.sortby,
    filter: input.filter,
  };
}

interface ResultPage {
  items?: unknown[];
  total_items?: number;
  limit?: number;
  [key: string]: unknown;
}

function withNextFrom(page: ResultPage, from: number): unknown {
  const items = page.items ?? [];
  const total = page.total_items;
  const nextFrom = typeof total === 'number' && from + items.length < total ? from + items.length : undefined;
  return { ...page, from, nextFrom };
}

async function listPage(
  client: Action1Client,
  path: string,
  input: PageInput,
  extra: Record<string, QueryValue> = {},
): Promise<unknown> {
  const from = input.from ?? 0;
  const page = await client.get<ResultPage>(path, { ...pageQuery(input), ...extra });
  return withNextFrom(page, from);
}

const org = (orgId: string) => encodeURIComponent(orgId);

// --- Organizations ---

export async function listOrganizations(client: Action1Client, input: PageInput = {}): Promise<unknown> {
  return listPage(client, '/organizations', input);
}

// --- Endpoints ---

export interface ListEndpointsInput extends PageInput {
  orgId: string;
  endpointStatus?: string;
  onlineStatus?: string;
  updateStatus?: string;
  vulnerabilityStatus?: string;
  rebootRequired?: string;
  endpointOS?: string;
  fields?: string;
}

export async function listEndpoints(client: Action1Client, input: ListEndpointsInput): Promise<unknown> {
  return listPage(client, `/endpoints/managed/${org(input.orgId)}`, input, {
    endpointStatus: input.endpointStatus,
    onlineStatus: input.onlineStatus,
    updateStatus: input.updateStatus,
    vulnerabilityStatus: input.vulnerabilityStatus,
    rebootRequired: input.rebootRequired,
    endpointOS: input.endpointOS,
    fields: input.fields,
  });
}

export async function getEndpoint(
  client: Action1Client,
  input: { orgId: string; endpointId: string; includeMissingUpdates?: boolean },
): Promise<unknown> {
  const base = `/endpoints/managed/${org(input.orgId)}/${encodeURIComponent(input.endpointId)}`;
  if (input.includeMissingUpdates) {
    const [endpoint, missingUpdates] = await Promise.all([
      client.get(base),
      client.get(`${base}/missing-updates`),
    ]);
    return { endpoint, missingUpdates };
  }
  return client.get(base);
}

export async function listEndpointGroups(
  client: Action1Client,
  input: { orgId: string; groupId?: string; contents?: boolean } & PageInput,
): Promise<unknown> {
  const base = `/endpoints/groups/${org(input.orgId)}`;
  if (input.groupId) {
    const groupPath = `${base}/${encodeURIComponent(input.groupId)}`;
    return input.contents ? listPage(client, `${groupPath}/contents`, input) : client.get(groupPath);
  }
  return listPage(client, base, input);
}

// --- Updates / patching ---

export interface ListUpdatesInput extends PageInput {
  orgId: string;
  packageId?: string;
  approvalStatus?: string;
  securitySeverity?: string;
  onlyLatest?: boolean;
  builtin?: string;
  custom?: string;
  fields?: string;
}

export async function listUpdates(client: Action1Client, input: ListUpdatesInput): Promise<unknown> {
  if (input.packageId) {
    return client.get(`/updates/${org(input.orgId)}/${encodeURIComponent(input.packageId)}`);
  }
  return listPage(client, `/updates/${org(input.orgId)}`, input, {
    approval_status: input.approvalStatus,
    security_severity: input.securitySeverity,
    only_latest: input.onlyLatest === undefined ? undefined : input.onlyLatest ? 'Yes' : 'No',
    builtin: input.builtin,
    custom: input.custom,
    fields: input.fields,
  });
}

export interface SetUpdateApprovalsInput {
  orgId: string;
  /** Approval records as the Action1 API expects them: {id, version, approval_status}. */
  approvals: Array<Record<string, unknown>>;
}

export async function setUpdateApprovals(client: Action1Client, input: SetUpdateApprovalsInput): Promise<unknown> {
  assertWritesEnabled('action1_set_update_approvals');
  if (input.orgId === 'all') {
    throw new Error('Refusing to change approvals for ALL organizations at once — pass a specific orgId.');
  }
  return client.post(`/updates/${org(input.orgId)}/approvals`, input.approvals);
}

// --- Vulnerabilities ---

export interface ListVulnerabilitiesInput extends PageInput {
  orgId: string;
  cveId?: string;
  detail?: 'endpoints' | 'remediations';
  score?: string;
  remediationStatus?: string;
  endpointId?: string;
}

export async function listVulnerabilities(client: Action1Client, input: ListVulnerabilitiesInput): Promise<unknown> {
  const base = `/vulnerabilities/${org(input.orgId)}`;
  if (input.cveId) {
    const cvePath = `${base}/${encodeURIComponent(input.cveId)}`;
    if (input.detail) {
      return listPage(client, `${cvePath}/${input.detail}`, input);
    }
    return client.get(cvePath);
  }
  return listPage(client, base, input, {
    score: input.score,
    remediation_status: input.remediationStatus,
    endpoint_id: input.endpointId,
  });
}

// --- Software ---

export async function getInstalledSoftware(
  client: Action1Client,
  input: { orgId: string; endpointId?: string } & PageInput,
): Promise<unknown> {
  const base = `/installed-software/${org(input.orgId)}/data`;
  if (input.endpointId) {
    return listPage(client, `${base}/${encodeURIComponent(input.endpointId)}`, input);
  }
  return listPage(client, base, input);
}

export async function listSoftwareRepository(
  client: Action1Client,
  input: { orgId: string; packageId?: string } & PageInput,
): Promise<unknown> {
  const base = `/software-repository/${org(input.orgId)}`;
  if (input.packageId) {
    return client.get(`${base}/${encodeURIComponent(input.packageId)}`);
  }
  return listPage(client, base, input);
}

export async function listScripts(
  client: Action1Client,
  input: { scriptId?: string } & PageInput = {},
): Promise<unknown> {
  if (input.scriptId) {
    return client.get(`/scripts/all/${encodeURIComponent(input.scriptId)}`);
  }
  return listPage(client, '/scripts/all', input);
}

// --- Automations ---

export interface ListAutomationsInput extends PageInput {
  orgId: string;
  kind: 'schedules' | 'instances';
  automationId?: string;
  endpointResults?: boolean;
}

export async function listAutomations(client: Action1Client, input: ListAutomationsInput): Promise<unknown> {
  const base = `/automations/${input.kind}/${org(input.orgId)}`;
  if (input.automationId) {
    const itemPath = `${base}/${encodeURIComponent(input.automationId)}`;
    if (input.endpointResults && input.kind === 'instances') {
      return listPage(client, `${itemPath}/endpoint-results`, input);
    }
    return client.get(itemPath);
  }
  return listPage(client, base, input);
}

// --- Reports ---

export async function listReports(client: Action1Client, input: PageInput = {}): Promise<unknown> {
  return listPage(client, '/reports/all', input);
}

export async function getReportData(
  client: Action1Client,
  input: { orgId: string; reportId: string } & PageInput,
): Promise<unknown> {
  return listPage(client, `/reportdata/${org(input.orgId)}/${encodeURIComponent(input.reportId)}/data`, input);
}

// --- Audit ---

export async function getAuditLog(
  client: Action1Client,
  input: { orgId?: string } & PageInput = {},
): Promise<unknown> {
  if (input.orgId) {
    return listPage(client, `/logs/${org(input.orgId)}`, input);
  }
  return listPage(client, '/audit/events', input);
}
