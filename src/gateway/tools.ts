import { z } from 'zod/v4';
import { writeGatewayAuditEvent } from './audit.js';
import type { Action1GatewayClient } from './client.js';
import {
  checkConnection,
  GATEWAY_MAX_LIMIT,
  getEndpoint,
  getInstalledSoftware,
  getReportData,
  listEndpointGroups,
  listEndpoints,
  listOrganizations,
  listReports,
  listUpdates,
  listVulnerabilities,
  setUpdateApprovals,
} from './ops.js';
import { currentInstancePolicy, currentOfferedTools, TOOL_PREFIX } from './scope.js';

/**
 * The tools of the embedded gateway (src/gateway.ts): one table with the
 * definition, the strict input schema, the Action1 requests each tool may
 * make and the handler. Reads only, and one change: approving or declining
 * updates. Nothing runs a script, installs or removes software, reboots a
 * machine or deletes; scripts, automations and the software repository are
 * not offered. The MCP server's own tools (src/tools/action1.ts) are
 * unchanged.
 */

export type GatewayRiskLevel = 'read' | 'write' | 'destructive';

export interface GatewayUpstreamOperation {
  readonly method: 'GET' | 'POST';
  readonly path: string;
}

export interface GatewayTool {
  /** Name without the prefix. */
  name: string;
  title: string;
  description: string;
  riskLevel: GatewayRiskLevel;
  /** The first line of a successful result's text. */
  summary: string;
  upstream: readonly GatewayUpstreamOperation[];
  broad?: boolean;
  schema: z.ZodObject;
  run: (client: Action1GatewayClient, input: Record<string, unknown>) => Promise<unknown>;
}

const TOKEN: GatewayUpstreamOperation = { method: 'POST', path: '/oauth2/token' };
const get = (path: string): GatewayUpstreamOperation => ({ method: 'GET', path });
const post = (path: string): GatewayUpstreamOperation => ({ method: 'POST', path });

const id = (what: string) => z.string().trim().min(1).max(200).describe(what);
const orgId = id('Organization id from list_organizations, or "all" for every organization the credentials can see.');
const pageShape = {
  search: z.string().trim().min(1).max(200).optional().describe('Text matched against any field (case-insensitive).'),
  limit: z.number().int().min(1).max(GATEWAY_MAX_LIMIT).optional().describe('Rows per page (default 50, at most 100).'),
  from: z.number().int().min(0).max(1_000_000).optional().describe('Offset: the nextFrom of the previous page.'),
};
const status3 = z.enum(['SUCCESS', 'WARNING', 'ERROR']);

const defineTools = (tools: GatewayTool[]): GatewayTool[] => tools;

export const GATEWAY_TOOLS: readonly GatewayTool[] = defineTools([
  {
    name: 'search_capabilities',
    title: 'Search Action1 capabilities',
    description: 'Find the Action1 tools this connection offers.',
    riskLevel: 'read',
    summary: 'Action1 capabilities.',
    upstream: [],
    schema: z.strictObject({
      query: z.string().trim().max(500).default(''),
      limit: z.number().int().min(1).max(50).default(20),
    }),
    run: async (_client, input) => searchCapabilities(String(input.query ?? ''), Number(input.limit ?? 20)),
  },
  {
    name: 'check_connection',
    title: 'Check Action1 connection',
    description: 'Verify that Action1 accepts the API credentials, and count the organizations they can see.',
    riskLevel: 'read',
    summary: 'Action1 connection checked.',
    upstream: [TOKEN, get('/organizations')],
    schema: z.strictObject({}),
    run: client => checkConnection(client),
  },
  {
    name: 'list_organizations',
    title: 'List Action1 organizations',
    description: 'List the organizations the credentials can see (id, name, description). Other tools need an organization id.',
    riskLevel: 'read',
    summary: 'Action1 organizations.',
    upstream: [TOKEN, get('/organizations')],
    schema: z.strictObject({ ...pageShape }),
    run: (client, input) => listOrganizations(client, input),
  },
  {
    name: 'list_endpoints',
    title: 'List Action1 endpoints',
    description:
      'List managed computers: name, OS, connection and online status, last seen, last boot, reboot required, update and vulnerability status with counts of missing critical and other updates, and the logged-in user name. IP and MAC addresses, serial numbers and custom attributes are not returned.',
    riskLevel: 'read',
    summary: 'Action1 endpoints.',
    upstream: [TOKEN, get('/endpoints/managed/{orgId}')],
    schema: z.strictObject({
      orgId,
      status: z.enum(['Connected', 'Disconnected', 'Pending Uninstall']).optional(),
      onlineStatus: status3.optional(),
      updateStatus: status3.optional().describe('ERROR: critical updates missing; WARNING: other updates missing.'),
      vulnerabilityStatus: status3.optional(),
      rebootRequired: z.enum(['Yes', 'No']).optional(),
      ...pageShape,
    }),
    run: (client, input) => listEndpoints(client, input as never),
  },
  {
    name: 'get_endpoint',
    title: 'Get Action1 endpoint',
    description: 'Fetch one managed computer, and with includeMissingUpdates the updates it is missing (up to 100).',
    riskLevel: 'read',
    summary: 'Action1 endpoint.',
    upstream: [TOKEN, get('/endpoints/managed/{orgId}/{endpointId}'), get('/endpoints/managed/{orgId}/{endpointId}/missing-updates')],
    schema: z.strictObject({
      orgId,
      endpointId: id('Endpoint id from list_endpoints.'),
      includeMissingUpdates: z.boolean().default(false),
    }),
    run: (client, input) => getEndpoint(client, input as never),
  },
  {
    name: 'list_endpoint_groups',
    title: 'List Action1 endpoint groups',
    description: 'List endpoint groups (id, name, description), one group by groupId, or with members the computers in it.',
    riskLevel: 'read',
    summary: 'Action1 endpoint groups.',
    upstream: [
      TOKEN,
      get('/endpoints/groups/{orgId}'),
      get('/endpoints/groups/{orgId}/{groupId}'),
      get('/endpoints/groups/{orgId}/{groupId}/contents'),
    ],
    schema: z.strictObject({
      orgId,
      groupId: id('Group id from list_endpoint_groups.').optional(),
      members: z.boolean().default(false).describe('With groupId: list the computers in the group.'),
      ...pageShape,
    }),
    run: (client, input) => listEndpointGroups(client, input as never),
  },
  {
    name: 'list_updates',
    title: 'List Action1 missing updates',
    description:
      'Updates missing on the computers (operating system and apps), each with its versions: release date, severity, type, approval status (New, Approved, Declined) and patch deadline. packageId fetches one update. The package and version ids are what set_update_approvals takes.',
    riskLevel: 'read',
    summary: 'Action1 missing updates.',
    upstream: [TOKEN, get('/updates/{orgId}'), get('/updates/{orgId}/{packageId}')],
    schema: z.strictObject({
      orgId,
      packageId: id('Update package id from list_updates.').optional(),
      approvalStatus: z.enum(['New', 'Approved', 'Declined']).optional(),
      securitySeverity: z.enum(['Critical', 'Important', 'Moderate', 'Low', 'Unspecified']).optional(),
      onlyLatest: z.boolean().optional().describe('Only the latest version of each update.'),
      ...pageShape,
    }),
    run: (client, input) => listUpdates(client, input as never),
  },
  {
    name: 'list_vulnerabilities',
    title: 'List Action1 vulnerabilities',
    description:
      'Known vulnerabilities (CVEs) on the computers: score, publication date, whether it is known to be exploited (CISA KEV), remediation status and deadline, number of computers and the software affected. cveId fetches one CVE; with detail=endpoints the computers it affects, with detail=remediations the compensating controls recorded for it.',
    riskLevel: 'read',
    summary: 'Action1 vulnerabilities.',
    upstream: [
      TOKEN,
      get('/vulnerabilities/{orgId}'),
      get('/vulnerabilities/{orgId}/{cveId}'),
      get('/vulnerabilities/{orgId}/{cveId}/endpoints'),
      get('/vulnerabilities/{orgId}/{cveId}/remediations'),
    ],
    schema: z.strictObject({
      orgId,
      cveId: z.string().trim().min(9).max(30).optional().describe('A CVE id such as CVE-2026-12345.'),
      detail: z.enum(['endpoints', 'remediations']).optional(),
      score: z.enum(['Critical', 'High', 'Medium', 'Low']).optional(),
      remediationStatus: z
        .enum(['Overdue', 'Due_soon', 'Overdue_due_soon', 'Due_later', 'Control_applied', 'All_except_control_applied'])
        .optional(),
      endpointId: id('Only vulnerabilities on this endpoint.').optional(),
      ...pageShape,
    }),
    run: (client, input) => listVulnerabilities(client, input as never),
  },
  {
    name: 'get_installed_software',
    title: 'Get Action1 installed software',
    description:
      'Installed software across the organization (name, vendor, version, platform, number of computers, update status), or on one computer with endpointId.',
    riskLevel: 'read',
    summary: 'Action1 installed software.',
    upstream: [TOKEN, get('/installed-software/{orgId}/data'), get('/installed-software/{orgId}/data/{endpointId}')],
    schema: z.strictObject({ orgId, endpointId: id('Endpoint id from list_endpoints.').optional(), ...pageShape }),
    run: (client, input) => getInstalledSoftware(client, input as never),
  },
  {
    name: 'list_reports',
    title: 'List Action1 reports',
    description: 'List the built-in and custom reports (id, name, description). get_report_data reads one.',
    riskLevel: 'read',
    summary: 'Action1 reports.',
    upstream: [TOKEN, get('/reports/all')],
    schema: z.strictObject({ ...pageShape }),
    run: (client, input) => listReports(client, input),
  },
  {
    name: 'get_report_data',
    title: 'Get Action1 report data',
    description:
      'The rows of one report for an organization. Only the inventory, update and vulnerability columns are returned, never another column, and never a value that looks like a mail, IP or MAC address.',
    riskLevel: 'read',
    summary: 'Action1 report data.',
    upstream: [TOKEN, get('/reportdata/{orgId}/{reportId}/data')],
    schema: z.strictObject({ orgId, reportId: id('Report id from list_reports.'), ...pageShape }),
    run: (client, input) => getReportData(client, input as never),
  },
  {
    name: 'set_update_approvals',
    title: 'Set Action1 update approvals',
    description:
      'Approve or decline update versions for one organization, or set them back to New. Approved updates are what Action1’s own schedules install; nothing is installed by this call. Package and version ids come from list_updates. The organization "all" is refused.',
    riskLevel: 'write',
    summary: 'Action1 update approvals set.',
    upstream: [TOKEN, post('/updates/{orgId}/approvals')],
    schema: z.strictObject({
      orgId: id('Organization id from list_organizations (one organization, not "all").'),
      approvalStatus: z.enum(['Approved', 'Declined', 'New']),
      packages: z
        .array(
          z.strictObject({
            packageId: id('Update package id from list_updates.'),
            versionId: id('Version id of that update from list_updates.'),
          }),
        )
        .min(1)
        .max(50),
    }),
    run: (client, input) => setUpdateApprovals(client, input as never),
  },
]);

export const GATEWAY_TOOL_NAMES: readonly string[] = GATEWAY_TOOLS.map(tool => `${TOOL_PREFIX}${tool.name}`);

/** The offered tools whose title or description shares a word with the query, best first; all of them without one. */
function searchCapabilities(query: string, limit: number): unknown {
  const offered = currentOfferedTools();
  const words = (text: string) => text.toLowerCase().split(/[^a-z0-9]+/).filter(word => word.length >= 3);
  const asked = words(query);
  const scored = GATEWAY_TOOLS.filter(tool => offered?.has(`${TOOL_PREFIX}${tool.name}`) ?? true).map((tool, order) => {
    const own = new Set(words(`${tool.name} ${tool.title} ${tool.description}`));
    return { tool, order, score: asked.filter(word => own.has(word)).length };
  });
  const hits = asked.length === 0 ? scored : scored.filter(entry => entry.score > 0).sort((a, b) => b.score - a.score || a.order - b.order);
  return {
    query,
    tools: hits.slice(0, limit).map(({ tool }) => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      riskLevel: tool.riskLevel,
    })),
  };
}

/** Whether the instance's policy lets this tool run. Always under a host policy (src/gateway.ts). */
function checkPolicy(tool: GatewayTool): { allowed: boolean; reason: string } {
  const policy = currentInstancePolicy();
  const name = `${TOOL_PREFIX}${tool.name}`;
  if (!policy) return { allowed: false, reason: 'no instance policy' };
  if (policy.disabledTools.has(name)) return { allowed: false, reason: 'tool is disabled on this instance by the embedding host' };
  if (tool.riskLevel === 'read') return { allowed: true, reason: 'read tool' };
  return policy.enableWrites
    ? { allowed: true, reason: 'writes enabled by the embedding host' }
    : { allowed: false, reason: 'writes are disabled. The embedding host has not enabled writes for this instance.' };
}

/** The ids a call is about (hashed in the audit record). */
function auditTarget(input: Record<string, unknown>): unknown {
  return {
    orgId: input.orgId,
    endpointId: input.endpointId,
    groupId: input.groupId,
    packageId: input.packageId,
    cveId: input.cveId,
    reportId: input.reportId,
    approvalStatus: input.approvalStatus,
    packages: input.packages,
  };
}

/** Runs a gateway tool: the host's policy first, then the audit's start record, the call, and its finish or error. */
export async function runGatewayTool(tool: GatewayTool, client: Action1GatewayClient, input: Record<string, unknown>): Promise<unknown> {
  const name = `${TOOL_PREFIX}${tool.name}`;
  const target = auditTarget(input);
  const policy = checkPolicy(tool);
  if (!policy.allowed) {
    await writeGatewayAuditEvent({ tool: name, action: 'policy_denied', target, reason: policy.reason });
    throw new Error(`Refused: ${policy.reason}.`);
  }
  await writeGatewayAuditEvent({ tool: name, action: 'start', target, reason: policy.reason });
  try {
    // A read tool gets a view of the client that cannot send a change.
    const view =
      tool.riskLevel === 'read'
        ? (Object.assign(Object.create(client) as Action1GatewayClient, {
            post: async () => {
              throw new Error(`Read tool ${tool.name} attempted a change in Action1; refused.`);
            },
          }) as Action1GatewayClient)
        : client;
    const result = await tool.run(view, input);
    await writeGatewayAuditEvent({ tool: name, action: 'finish', target, status: 'ok' });
    return result;
  } catch (error) {
    await writeGatewayAuditEvent({ tool: name, action: 'error', target, status: 'error', error });
    throw error;
  }
}
