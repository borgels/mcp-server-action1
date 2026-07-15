import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod/v4';
import { formatUnknownError } from '../errors.js';
import { writeAuditEvent } from '../action1/audit.js';
import {
  READ_TOOL_ANNOTATIONS,
  WRITE_TOOL_ANNOTATIONS,
  searchCapabilities,
} from '../action1/capabilities.js';
import type { Action1Client } from '../action1/client.js';
import { checkToolPolicy } from '../action1/policy.js';
import {
  getAuditLog,
  getEndpoint,
  getInstalledSoftware,
  getReportData,
  listAutomations,
  listEndpointGroups,
  listEndpoints,
  listOrganizations,
  listReports,
  listScripts,
  listSoftwareRepository,
  listUpdates,
  listVulnerabilities,
  MAX_LIMIT,
  setUpdateApprovals,
} from '../action1/resources.js';

const orgIdSchema = z.string().trim().min(1).describe('Organization id (action1_list_organizations); many tools accept "all".');
const pageShape = {
  limit: z.number().int().min(1).max(MAX_LIMIT).optional().describe('Items per page (default 50).'),
  from: z.number().int().min(0).optional().describe('Offset — pass the previous response\'s nextFrom to continue.'),
  sortby: z.string().trim().optional().describe('Sort field; prefix with "-" for descending.'),
  filter: z.string().trim().optional().describe('Case-insensitive substring matched against any field.'),
};

export function registerAction1Tools(server: McpServer, client: Action1Client): void {
  server.registerTool(
    'action1_search_capabilities',
    {
      title: 'Search Action1 Capabilities',
      description: 'Search the Action1 MCP server capabilities and examples. Use this first when deciding which tool to call.',
      inputSchema: {
        query: z.string().trim().default(''),
        limit: z.number().int().min(1).max(50).default(20),
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_search_capabilities', input, async () =>
        jsonToolResult(searchCapabilities(input.query, input.limit)),
      ),
  );

  server.registerTool(
    'action1_list_organizations',
    {
      title: 'List Organizations (Action1)',
      description: 'List the Action1 organizations this credential can access. Start here — other tools need an orgId.',
      inputSchema: { ...pageShape },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_organizations', input, async () =>
        jsonToolResult(await listOrganizations(client, input)),
      ),
  );

  server.registerTool(
    'action1_list_endpoints',
    {
      title: 'List Endpoints (Action1)',
      description:
        'Inventory of managed endpoints: name, OS, agent status, last seen, update/vulnerability status, reboot-required. All status filters accept the values shown in the Action1 console. fields="*" adds extended data.',
      inputSchema: {
        orgId: orgIdSchema,
        endpointStatus: z.string().trim().optional(),
        onlineStatus: z.string().trim().optional(),
        updateStatus: z.string().trim().optional(),
        vulnerabilityStatus: z.string().trim().optional(),
        rebootRequired: z.string().trim().optional(),
        endpointOS: z.string().trim().optional(),
        fields: z.string().trim().optional().describe('Comma-separated extended fields, or "*" for all.'),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_endpoints', input, async () => jsonToolResult(await listEndpoints(client, input))),
  );

  server.registerTool(
    'action1_get_endpoint',
    {
      title: 'Get Endpoint (Action1)',
      description: 'Fetch one managed endpoint; includeMissingUpdates=true also returns its missing updates.',
      inputSchema: {
        orgId: orgIdSchema,
        endpointId: z.string().trim().min(1),
        includeMissingUpdates: z.boolean().default(false),
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_get_endpoint', input, async () => jsonToolResult(await getEndpoint(client, input))),
  );

  server.registerTool(
    'action1_list_endpoint_groups',
    {
      title: 'List Endpoint Groups (Action1)',
      description: 'List endpoint groups, one group (groupId), or its member endpoints (contents=true).',
      inputSchema: {
        orgId: orgIdSchema,
        groupId: z.string().trim().min(1).optional(),
        contents: z.boolean().default(false),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_endpoint_groups', input, async () =>
        jsonToolResult(await listEndpointGroups(client, input)),
      ),
  );

  server.registerTool(
    'action1_list_updates',
    {
      title: 'List Updates/Patches (Action1)',
      description:
        'Available updates with approval status, severity, and affected endpoints. Filters: approvalStatus (New/Approved/Declined), securitySeverity, onlyLatest. packageId fetches a single update.',
      inputSchema: {
        orgId: orgIdSchema,
        packageId: z.string().trim().min(1).optional(),
        approvalStatus: z.string().trim().optional(),
        securitySeverity: z.string().trim().optional(),
        onlyLatest: z.boolean().optional(),
        builtin: z.string().trim().optional(),
        custom: z.string().trim().optional(),
        fields: z.string().trim().optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_updates', input, async () => jsonToolResult(await listUpdates(client, input))),
  );

  server.registerTool(
    'action1_list_vulnerabilities',
    {
      title: 'List Vulnerabilities (Action1)',
      description:
        'CVEs across endpoints with score and remediation status. cveId fetches one CVE; detail=endpoints|remediations lists affected machines or available fixes.',
      inputSchema: {
        orgId: orgIdSchema,
        cveId: z.string().trim().min(1).optional(),
        detail: z.enum(['endpoints', 'remediations']).optional(),
        score: z.string().trim().optional(),
        remediationStatus: z.string().trim().optional(),
        endpointId: z.string().trim().optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_vulnerabilities', input, async () =>
        jsonToolResult(await listVulnerabilities(client, input)),
      ),
  );

  server.registerTool(
    'action1_get_installed_software',
    {
      title: 'Get Installed Software (Action1)',
      description: 'Installed software inventory for the organization, or one endpoint with endpointId.',
      inputSchema: {
        orgId: orgIdSchema,
        endpointId: z.string().trim().min(1).optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_get_installed_software', input, async () =>
        jsonToolResult(await getInstalledSoftware(client, input)),
      ),
  );

  server.registerTool(
    'action1_list_software_repository',
    {
      title: 'List Software Repository (Action1)',
      description: 'Deployable packages in the software repository (read-only).',
      inputSchema: {
        orgId: orgIdSchema,
        packageId: z.string().trim().min(1).optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_software_repository', input, async () =>
        jsonToolResult(await listSoftwareRepository(client, input)),
      ),
  );

  server.registerTool(
    'action1_list_scripts',
    {
      title: 'List Script Library (Action1)',
      description: 'The script library, read-only. This server can NOT run or edit scripts by design.',
      inputSchema: {
        scriptId: z.string().trim().min(1).optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_scripts', input, async () => jsonToolResult(await listScripts(client, input))),
  );

  server.registerTool(
    'action1_list_automations',
    {
      title: 'List Automations (Action1)',
      description:
        'Scheduled automations (kind=schedules) or run history (kind=instances); endpointResults=true lists per-endpoint outcomes for one instance. Read-only — creating/running automations is deliberately not exposed.',
      inputSchema: {
        orgId: orgIdSchema,
        kind: z.enum(['schedules', 'instances']),
        automationId: z.string().trim().min(1).optional(),
        endpointResults: z.boolean().default(false),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_automations', input, async () =>
        jsonToolResult(await listAutomations(client, input)),
      ),
  );

  server.registerTool(
    'action1_list_reports',
    {
      title: 'List Reports (Action1)',
      description: 'List available built-in and custom reports.',
      inputSchema: { ...pageShape },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_list_reports', input, async () => jsonToolResult(await listReports(client, input))),
  );

  server.registerTool(
    'action1_get_report_data',
    {
      title: 'Get Report Data (Action1)',
      description: 'Fetch the data rows of a report for an organization.',
      inputSchema: {
        orgId: orgIdSchema,
        reportId: z.string().trim().min(1),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_get_report_data', input, async () => jsonToolResult(await getReportData(client, input))),
  );

  server.registerTool(
    'action1_get_audit_log',
    {
      title: 'Get Audit Log (Action1)',
      description: 'Enterprise-wide audit events, or org-scoped logs with orgId.',
      inputSchema: {
        orgId: z.string().trim().min(1).optional(),
        ...pageShape,
      },
      annotations: READ_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_get_audit_log', input, async () => jsonToolResult(await getAuditLog(client, input))),
  );

  server.registerTool(
    'action1_set_update_approvals',
    {
      title: 'Set Update Approvals (Action1)',
      description:
        'Approve/decline updates for ONE organization. Approved updates are what scheduled automations deploy — confirm the list with the user before approving. Requires write access on this instance; orgId="all" is refused.',
      inputSchema: {
        orgId: orgIdSchema,
        approvals: z
          .array(z.record(z.string(), z.unknown()))
          .min(1)
          .max(100)
          .describe('Approval records, e.g. [{id, version, approval_status: "Approved"}].'),
      },
      annotations: WRITE_TOOL_ANNOTATIONS,
    },
    async input =>
      runAuditedTool('action1_set_update_approvals', input, async () =>
        jsonToolResult(await setUpdateApprovals(client, input)),
      ),
  );
}

async function runAuditedTool<T>(tool: string, input: unknown, call: () => Promise<T>): Promise<T> {
  const policy = checkToolPolicy(tool);
  const target = auditTarget(input);

  if (!policy.allowed) {
    await writeAuditEvent({ tool, action: 'policy_denied', target, reason: policy.reason });
    throw new Error(policy.reason);
  }

  await writeAuditEvent({ tool, action: 'start', target, reason: policy.reason });

  try {
    const result = await call();
    await writeAuditEvent({ tool, action: 'finish', target, status: 'ok' });
    return result;
  } catch (error) {
    await writeAuditEvent({
      tool,
      action: 'error',
      target,
      status: 'error',
      error: formatUnknownError(error),
    });
    throw error;
  }
}

function auditTarget(input: unknown): unknown {
  if (!input || typeof input !== 'object') {
    return input;
  }
  const value = input as Record<string, unknown>;
  return {
    orgId: value.orgId,
    endpointId: value.endpointId,
    groupId: value.groupId,
    packageId: value.packageId,
    cveId: value.cveId,
    scriptId: value.scriptId,
    automationId: value.automationId,
    reportId: value.reportId,
    kind: value.kind,
    detail: value.detail,
    approvalCount: Array.isArray(value.approvals) ? value.approvals.length : undefined,
    query: value.query,
    filter: value.filter,
  };
}

function jsonToolResult(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2),
      },
    ],
  };
}
