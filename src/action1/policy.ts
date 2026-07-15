/**
 * Action1 is an RMM platform: parts of its API can execute arbitrary code
 * on every managed endpoint. This server deliberately exposes NO tools for:
 *  - creating/running automations (run_script / deploy / reboot — RCE),
 *  - remote-desktop sessions,
 *  - software-repository writes (supply-chain risk),
 *  - deleting/moving endpoints, user/role/org management, enterprise closure.
 * If script execution is ever wanted, it belongs behind a dedicated
 * duty-gated commit tool (like e-conomic booking), not a generic flag.
 *
 * The one write tool (patch approvals) requires ACTION1_ENABLE_WRITES=true.
 */
export function writesEnabled(): boolean {
  return process.env.ACTION1_ENABLE_WRITES === 'true';
}

export function assertWritesEnabled(action: string): void {
  if (!writesEnabled()) {
    throw new Error(
      `Write access is disabled on this Action1 MCP instance (${action}). ` +
        'Set ACTION1_ENABLE_WRITES=true in the server environment to allow write tools.',
    );
  }
}

export interface Action1PolicyDecision {
  allowed: boolean;
  reason: string;
}

const READ_TOOLS = new Set([
  'action1_search_capabilities',
  'action1_list_organizations',
  'action1_list_endpoints',
  'action1_get_endpoint',
  'action1_list_endpoint_groups',
  'action1_list_updates',
  'action1_list_vulnerabilities',
  'action1_get_installed_software',
  'action1_list_software_repository',
  'action1_list_scripts',
  'action1_list_automations',
  'action1_list_reports',
  'action1_get_report_data',
  'action1_get_audit_log',
]);

const WRITE_TOOLS = new Set(['action1_set_update_approvals']);

export function checkToolPolicy(toolName: string): Action1PolicyDecision {
  if (READ_TOOLS.has(toolName)) {
    return { allowed: true, reason: 'read-only Action1 tool' };
  }
  if (WRITE_TOOLS.has(toolName)) {
    if (!writesEnabled()) {
      return {
        allowed: false,
        reason: `write tool is disabled on this instance (ACTION1_ENABLE_WRITES != true): ${toolName}`,
      };
    }
    return { allowed: true, reason: 'write tool (writes enabled on this instance)' };
  }
  return { allowed: false, reason: `tool is not allowlisted: ${toolName}` };
}
