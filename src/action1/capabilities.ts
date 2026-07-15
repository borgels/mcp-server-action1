export type CapabilityRisk = 'read' | 'write';

export interface Action1Capability {
  id: string;
  title: string;
  description: string;
  risk: CapabilityRisk;
  examples: unknown[];
  identifierFormats: string[];
  safetyNotes: string[];
  keywords: string[];
}

export const READ_TOOL_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export const WRITE_TOOL_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

const PAGINATION_NOTE =
  'Lists return {items, total_items, from, nextFrom}; pass nextFrom as `from` to continue. Action1 recommends < 30 requests/min for the whole enterprise.';
const ORG_NOTE = 'orgId comes from action1_list_organizations; many read endpoints also accept "all".';

export const ACTION1_CAPABILITIES: Action1Capability[] = [
  {
    id: 'action1_search_capabilities',
    title: 'Search Action1 Capabilities',
    description: 'Find the Action1 MCP tool for endpoint inventory, patching, vulnerabilities, software, or reports.',
    risk: 'read',
    examples: [{ query: 'missing patches' }],
    identifierFormats: ['Tool id such as action1_list_endpoints or action1_list_updates.'],
    safetyNotes: ['Discovery only. Does not call Action1.'],
    keywords: ['discover', 'help', 'capabilities'],
  },
  {
    id: 'action1_list_organizations',
    title: 'List Organizations (Action1)',
    description: 'List the Action1 organizations the API credential can see. Start here — every other tool needs an orgId.',
    risk: 'read',
    examples: [{}],
    identifierFormats: ['org id (string)'],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['organizations', 'organisationer', 'tenants', 'start'],
  },
  {
    id: 'action1_list_endpoints',
    title: 'List Endpoints (Action1)',
    description:
      'Inventory of managed endpoints (computers/servers): name, OS, status, last seen, missing updates, vulnerability status, reboot-required. Filterable on all of those; `filter` is free-text substring; fields="*" adds extended data.',
    risk: 'read',
    examples: [{ orgId: 'all' }, { orgId: '123', updateStatus: 'Missing critical updates' }],
    identifierFormats: [ORG_NOTE],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['endpoints', 'computers', 'maskiner', 'devices', 'enheder', 'servers', 'inventory', 'online'],
  },
  {
    id: 'action1_get_endpoint',
    title: 'Get Endpoint (Action1)',
    description: 'Fetch one endpoint with full details; includeMissingUpdates=true also fetches its missing updates.',
    risk: 'read',
    examples: [{ orgId: '123', endpointId: 'abc', includeMissingUpdates: true }],
    identifierFormats: ['endpointId from action1_list_endpoints'],
    safetyNotes: [],
    keywords: ['endpoint', 'device', 'maskine', 'details', 'missing updates'],
  },
  {
    id: 'action1_list_endpoint_groups',
    title: 'List Endpoint Groups (Action1)',
    description: 'List endpoint groups, one group, or its member endpoints (contents=true).',
    risk: 'read',
    examples: [{ orgId: '123' }, { orgId: '123', groupId: 'g1', contents: true }],
    identifierFormats: [ORG_NOTE],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['groups', 'grupper', 'endpoint groups'],
  },
  {
    id: 'action1_list_updates',
    title: 'List Updates/Patches (Action1)',
    description:
      'Patch overview: available updates with approval status, severity, affected endpoints. Filters: approvalStatus (New/Approved/Declined), securitySeverity, onlyLatest. packageId fetches one update.',
    risk: 'read',
    examples: [{ orgId: 'all', approvalStatus: 'New', securitySeverity: 'Critical' }],
    identifierFormats: [ORG_NOTE, 'approvalStatus: New | Approved | Declined'],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['updates', 'patches', 'opdateringer', 'patching', 'approval', 'severity', 'kb'],
  },
  {
    id: 'action1_list_vulnerabilities',
    title: 'List Vulnerabilities (Action1)',
    description:
      'CVE overview across endpoints: score, remediation status. cveId fetches one CVE; detail=endpoints|remediations lists affected machines or fixes.',
    risk: 'read',
    examples: [{ orgId: 'all' }, { orgId: '123', cveId: 'CVE-2026-1234', detail: 'endpoints' }],
    identifierFormats: [ORG_NOTE, 'cveId: CVE-YYYY-NNNN'],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['vulnerabilities', 'sårbarheder', 'cve', 'security', 'remediation'],
  },
  {
    id: 'action1_get_installed_software',
    title: 'Get Installed Software (Action1)',
    description: 'Installed software inventory across the org, or for one endpoint (endpointId).',
    risk: 'read',
    examples: [{ orgId: '123' }, { orgId: '123', endpointId: 'abc' }],
    identifierFormats: [ORG_NOTE],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['software', 'installed', 'installeret', 'programmer', 'applications', 'inventory'],
  },
  {
    id: 'action1_list_software_repository',
    title: 'List Software Repository (Action1)',
    description: 'Deployable packages in the software repository (read-only — this server cannot modify the repository).',
    risk: 'read',
    examples: [{ orgId: 'all' }],
    identifierFormats: [ORG_NOTE],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['repository', 'packages', 'pakker', 'deploy'],
  },
  {
    id: 'action1_list_scripts',
    title: 'List Script Library (Action1)',
    description: 'The script library (read-only — this server can NOT run or edit scripts).',
    risk: 'read',
    examples: [{}],
    identifierFormats: ['scriptId for one script'],
    safetyNotes: ['Read-only by design; script execution is deliberately not exposed.'],
    keywords: ['scripts', 'library', 'powershell'],
  },
  {
    id: 'action1_list_automations',
    title: 'List Automations (Action1)',
    description:
      'Scheduled automations (kind=schedules) or run history (kind=instances) with per-endpoint results (endpointResults=true). Read-only — this server cannot create or run automations.',
    risk: 'read',
    examples: [{ orgId: '123', kind: 'schedules' }, { orgId: '123', kind: 'instances', automationId: 'a1', endpointResults: true }],
    identifierFormats: [ORG_NOTE, 'kind: schedules | instances'],
    safetyNotes: ['Read-only by design; running automations (RCE-capable) is deliberately not exposed.'],
    keywords: ['automations', 'schedules', 'planlagt', 'runs', 'results', 'deployment'],
  },
  {
    id: 'action1_list_reports',
    title: 'List Reports (Action1)',
    description: 'List available built-in and custom reports.',
    risk: 'read',
    examples: [{}],
    identifierFormats: ['reportId for action1_get_report_data'],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['reports', 'rapporter'],
  },
  {
    id: 'action1_get_report_data',
    title: 'Get Report Data (Action1)',
    description: 'Fetch the data rows of a report for an organization.',
    risk: 'read',
    examples: [{ orgId: '123', reportId: 'installed_software' }],
    identifierFormats: ['reportId from action1_list_reports', ORG_NOTE],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['report data', 'rows', 'export'],
  },
  {
    id: 'action1_get_audit_log',
    title: 'Get Audit Log (Action1)',
    description: 'Enterprise audit events (who did what in Action1), or org-scoped logs with orgId.',
    risk: 'read',
    examples: [{}, { orgId: '123' }],
    identifierFormats: [],
    safetyNotes: [PAGINATION_NOTE],
    keywords: ['audit', 'log', 'events', 'historik', 'hvem'],
  },
  {
    id: 'action1_set_update_approvals',
    title: 'Set Update Approvals (Action1)',
    description:
      'Approve or decline updates for ONE organization (the patch-approval workflow gate). Approved updates are what scheduled automations deploy. Requires write access on this instance.',
    risk: 'write',
    examples: [{ orgId: '123', approvals: [{ id: 'pkg1', version: '1.2.3', approval_status: 'Approved' }] }],
    identifierFormats: ['approval_status: Approved | Declined | New'],
    safetyNotes: [
      'Requires ACTION1_ENABLE_WRITES=true.',
      'orgId="all" is refused — approvals must target a specific organization.',
      'Approval feeds scheduled deployments — confirm the list of updates with the user before approving.',
    ],
    keywords: ['approve', 'godkend', 'decline', 'afvis', 'patch approval', 'updates', 'write'],
  },
];

export function searchCapabilities(query: string, limit = 20): Action1Capability[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return ACTION1_CAPABILITIES.slice(0, limit);
  }
  return ACTION1_CAPABILITIES.map(capability => ({
    capability,
    score: scoreCapability(capability, normalized),
  }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || a.capability.id.localeCompare(b.capability.id))
    .slice(0, limit)
    .map(item => item.capability);
}

function scoreCapability(capability: Action1Capability, query: string): number {
  const haystack = [
    capability.id,
    capability.title,
    capability.description,
    ...capability.identifierFormats,
    ...capability.keywords,
  ]
    .join(' ')
    .toLowerCase();
  return query
    .split(/\s+/)
    .filter(Boolean)
    .reduce((score, term) => score + (haystack.includes(term) ? 1 : 0), 0);
}
