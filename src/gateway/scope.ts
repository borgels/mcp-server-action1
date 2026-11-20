import { AsyncLocalStorage } from 'node:async_hooks';
import type { SecretRedactor } from '../upstream-http.js';

/**
 * Call scopes for the embeddable gateway.
 *
 * An embedding host that serves several tenants from one process passes an
 * InstancePolicy to the gateway. Every call of a gateway instance runs under
 * an instance policy: the host's, or, when the host passes none, the default
 * one (no writes, no disabled tools, no audit). A gateway call therefore
 * reads none of ACTION1_ENABLE_WRITES or ACTION1_AUDIT_LOG,
 * so a tenant's settings never come from a value the whole process shares.
 *
 * Every gateway call runs in a scope of its own (runInCallScope), so a call
 * made from inside another instance's call (from its audit sink or its
 * fetch) never inherits that instance's policy, sink, redactor or caller.
 * Outside a gateway call (the MCP server) there is no scope and the
 * environment applies.
 */

/** Receives one audit record (the JSON object the audit log would hold). */
export type AuditSink = (record: Readonly<Record<string, unknown>>) => void | Promise<void>;

/** Policy given by an embedding host for one gateway instance. */
export interface InstancePolicy {
  /** Allow write tools. Default false. */
  enableWrites?: boolean;
  /** Tools turned off on this instance, with or without the `action1_` prefix. Must name gateway tools. */
  disabledTools?: readonly string[];
  /**
   * Receives every audit record of this instance's calls, instead of
   * ACTION1_AUDIT_LOG. Without it the instance writes no audit records. A tool
   * runs only if its start record was accepted, so a sink that throws
   * refuses the call.
   */
  audit?: AuditSink;
}

/** An InstancePolicy, checked and normalised. */
export interface ResolvedInstancePolicy {
  readonly enableWrites: boolean;
  readonly disabledTools: ReadonlySet<string>;
  readonly audit?: AuditSink;
}

/** Who and which request a call belongs to, as given by the embedding host. */
export interface CallContext {
  /** Caller identity (for example a user id). Written to audit records only as an HMAC pseudonym. */
  caller?: string;
  /**
   * The host's request id. Not written to audit records: in a gateway call they share a request id of the server's
   * own, generated per call.
   */
  requestId?: string;
}

/** What one gateway call runs under. */
export interface CallScope {
  /** The instance's policy; undefined (outside a gateway call) means the environment applies. */
  readonly policy?: ResolvedInstancePolicy;
  /** The instance's redactor. */
  readonly redactor?: SecretRedactor;
  readonly caller?: string;
  readonly requestId?: string;
  /** The prefixed names of the tools the instance offers; search_capabilities lists only these. */
  readonly offeredTools?: ReadonlySet<string>;
}

export const TOOL_PREFIX = 'action1_';

const callScope = new AsyncLocalStorage<CallScope>();

/** Thrown for an unusable host policy or gateway option. */
export class GatewayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayConfigError';
  }
}

/** Tool names are accepted with or without the prefix, case-insensitively. */
export function canonicalToolName(name: string): string {
  const lower = name.trim().toLowerCase();
  return lower.startsWith(TOOL_PREFIX) ? lower : `${TOOL_PREFIX}${lower}`;
}

/** Check a host's policy against the known tools. Throws GatewayConfigError on anything unclear, quoting no value. */
export function resolveInstancePolicy(policy: InstancePolicy, knownTools: readonly string[]): ResolvedInstancePolicy {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new GatewayConfigError('policy must be an object');
  }
  if (policy.enableWrites !== undefined && typeof policy.enableWrites !== 'boolean') {
    throw new GatewayConfigError('policy.enableWrites must be a boolean');
  }
  if (policy.disabledTools !== undefined && !Array.isArray(policy.disabledTools)) {
    throw new GatewayConfigError('policy.disabledTools must be an array of tool names');
  }
  if (policy.audit !== undefined && typeof policy.audit !== 'function') {
    throw new GatewayConfigError('policy.audit must be a function');
  }
  const known = new Set(knownTools);
  const disabled = new Set<string>();
  for (const [index, name] of (policy.disabledTools ?? []).entries()) {
    if (typeof name !== 'string' || !known.has(canonicalToolName(name))) {
      // The value is not quoted: configuration is never echoed, not even shortened.
      throw new GatewayConfigError(`policy.disabledTools[${index}] is not a known gateway tool.`);
    }
    disabled.add(canonicalToolName(name));
  }
  return Object.freeze({
    enableWrites: policy.enableWrites === true,
    disabledTools: disabled,
    ...(policy.audit ? { audit: policy.audit } : {}),
  });
}

/**
 * Run `work` (and everything it awaits) in a call scope of its own. Always a
 * fresh scope: a scope without a policy means the environment applies, even
 * when the caller is itself inside another instance's call.
 */
export function runInCallScope<T>(scope: CallScope, work: () => T): T {
  return callScope.run(Object.freeze({ ...scope }), work);
}

/** The host's policy of the call in progress, or undefined (the environment applies). */
export function currentInstancePolicy(): ResolvedInstancePolicy | undefined {
  return callScope.getStore()?.policy;
}

/** The redactor of the instance whose call is in progress, if any. */
export function currentRedactor(): SecretRedactor | undefined {
  return callScope.getStore()?.redactor;
}

/** Caller and request id of the gateway call in progress, if any. */
export function currentCallContext(): CallContext {
  const scope = callScope.getStore();
  return { caller: scope?.caller, requestId: scope?.requestId };
}

/** The tools the gateway instance whose call is in progress offers, or undefined (the MCP server: all of them). */
export function currentOfferedTools(): ReadonlySet<string> | undefined {
  return callScope.getStore()?.offeredTools;
}
