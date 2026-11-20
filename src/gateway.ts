import { randomUUID } from 'node:crypto';
import { z } from 'zod/v4';
import { fixedOutputs, withheldResult } from './fallbacks.js';
import { admitsKey, KEY_REFUSED, leaksSecret, maskedText, sealedError } from './key-admission.js';
import { redactDeep, redactText } from './redaction.js';
import { writeGatewayAuditEvent } from './gateway/audit.js';
import { Action1GatewayClient, ACTION1_REGIONS, type Action1Region } from './gateway/client.js';
import {
  canonicalToolName,
  GatewayConfigError,
  resolveInstancePolicy,
  runInCallScope,
  TOOL_PREFIX,
  type CallContext,
  type InstancePolicy,
  type ResolvedInstancePolicy,
} from './gateway/scope.js';
import {
  GATEWAY_TOOL_NAMES,
  GATEWAY_TOOLS,
  runGatewayTool,
  type GatewayRiskLevel,
  type GatewayTool,
  type GatewayUpstreamOperation,
} from './gateway/tools.js';
import { REDACTION_MARKER, SecretRedactor } from './upstream-http.js';

/**
 * Embeddable entry point (package export `./gateway`): an embedding host,
 * such as an MCP gateway that does its own per-user authorization, lists
 * `tools` and invokes `callTool`. The tools, their schemas and handlers live
 * in src/gateway/tools.ts and src/gateway/ops.ts.
 *
 * Several gateway instances (for example one per tenant) can run in one
 * process. Each instance uses only the client id, client secret and region
 * passed to createAction1Gateway and reads no ACTION1_* variable at all: not
 * the credentials (ACTION1_CLIENT_ID, ACTION1_CLIENT_SECRET), not the address
 * (ACTION1_BASE_URL: the region picks one of Action1's fixed API addresses),
 * not ACTION1_TIMEOUT_MS (30 seconds unless `timeoutMs` is given), not
 * ACTION1_ENABLE_WRITES (the host's policy decides) and not ACTION1_AUDIT_LOG.
 *
 * Instance policy (writes, disabled tools, audit) comes from the host when it
 * passes `policy`; without it the instance uses the default policy (no
 * writes, no disabled tools, no audit records).
 *
 * Every call runs in a call scope of its own (AsyncLocalStorage), so a call
 * made from inside another instance's call (from its audit sink or its fetch)
 * never inherits that instance's policy, sink, redactor or caller.
 */

export type { AuditSink, InstancePolicy } from './gateway/scope.js';
export type { Action1Region } from './gateway/client.js';
export type { GatewayRiskLevel, GatewayUpstreamOperation } from './gateway/tools.js';
export { GatewayConfigError } from './gateway/scope.js';
export { KEY_REFUSED } from './key-admission.js';

/** The regions a host may choose, each with Action1's fixed API address. */
export const ACTION1_REGION_IDS: readonly Action1Region[] = Object.freeze(Object.keys(ACTION1_REGIONS) as Action1Region[]);

export type GatewayJsonValue = string | number | boolean | null | GatewayJsonValue[] | { [key: string]: GatewayJsonValue };
export type GatewayJsonObject = { [key: string]: GatewayJsonValue };

export interface GatewayToolDefinition {
  name: string;
  title: string;
  description: string;
  riskLevel: GatewayRiskLevel;
  enabledByDefault: boolean;
  inputSchema: GatewayJsonObject;
}

export interface GatewayToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: GatewayJsonValue;
  isError?: boolean;
}

/** Who and which request a call belongs to; written to the audit records of the call. */
export type GatewayCallContext = CallContext;

/** Deeply read-only JSON, as found in the frozen tool catalog. */
export type GatewayReadonlyJsonValue =
  | string
  | number
  | boolean
  | null
  | readonly GatewayReadonlyJsonValue[]
  | { readonly [key: string]: GatewayReadonlyJsonValue };

/** A tool catalog entry: the gateway definition plus the upstream requests the tool may make. */
export interface GatewayToolCatalogEntry {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly riskLevel: GatewayRiskLevel;
  readonly enabledByDefault: boolean;
  readonly inputSchema: { readonly [key: string]: GatewayReadonlyJsonValue };
  /**
   * Every Action1 request the tool may make, relative to the region's API
   * address (…/api/3.0). Empty for a tool that does not call Action1.
   */
  readonly upstream: readonly GatewayUpstreamOperation[];
  /**
   * True when the tool can read more than its name says (anything in the
   * system, chosen by the input). No Action1 gateway tool is broad.
   */
  readonly broad: boolean;
}

export interface Action1GatewayOptions {
  /** The API client id (Action1 shows it as an e-mail-like id). Required; never read from the environment. */
  clientId: string;
  /** The API client secret. Required; never read from the environment. */
  clientSecret: string;
  /** The Action1 region of the account: eu, na, na2, uk or au. Required; never read from the environment. */
  region: Action1Region;
  /** The fetch to use (for tests and custom transports). Redirects are never followed either way. */
  fetchImpl?: typeof fetch;
  /** Time limit per Action1 request in milliseconds. Default 30 seconds; never read from the environment. */
  timeoutMs?: number;
  /**
   * Instance policy from the host. Without it the instance uses the default
   * policy (no writes, no disabled tools, no audit records); it never reads
   * a policy or audit variable from the environment.
   */
  policy?: InstancePolicy;
}

const DEFAULT_TIMEOUT_MS = 30_000;
/** What a client id may be: printable ASCII, as Action1 issues it. */
const CLIENT_ID = /^[\x21-\x7E]{8,320}$/;

/**
 * JSON Schema for a gateway tool, derived from the same zod schema the call
 * is validated with. `format` and `pattern` are dropped: validators such as
 * Ajv reject unknown formats in strict mode, and zod checks the values when
 * the call runs.
 */
function toJsonSchema(schema: z.ZodType): GatewayJsonObject {
  const { $schema: _ignored, ...json } = z.toJSONSchema(schema, {
    io: 'input',
    override: ctx => {
      delete (ctx.jsonSchema as Record<string, unknown>).format;
      delete (ctx.jsonSchema as Record<string, unknown>).pattern;
    },
  }) as Record<string, unknown>;
  return json as GatewayJsonObject;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

function definition(tool: GatewayTool): GatewayToolDefinition {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    riskLevel: tool.riskLevel,
    enabledByDefault: tool.riskLevel === 'read',
    inputSchema: toJsonSchema(tool.schema),
  };
}

/** All gateway tools, as definitions (names without the prefix). */
export const action1GatewayTools: GatewayToolDefinition[] = GATEWAY_TOOLS.map(definition);

/**
 * The tool catalog: every gateway tool with its definition, the upstream
 * requests it may make and the broad mark. Generated from the same table as
 * `action1GatewayTools` and deeply frozen. Hosts can use it to build their own
 * permission model without creating a gateway instance.
 */
export const action1ToolCatalog: readonly GatewayToolCatalogEntry[] = deepFreeze(
  GATEWAY_TOOLS.map(tool => ({
    ...definition(tool),
    upstream: tool.upstream.map(operation => ({ ...operation })),
    broad: tool.broad === true,
  })),
);

const TOOLS_BY_NAME: ReadonlyMap<string, GatewayTool> = new Map(GATEWAY_TOOLS.map(tool => [`${TOOL_PREFIX}${tool.name}`, tool]));

/** KEY_REFUSED with every run that shares a piece with any of the secrets masked, so it holds no piece of one. */
function refusedText(field: string, secrets: readonly unknown[]): string {
  return secrets.reduce<string>((text, secret) => maskedText(text, secret), `${field}: ${KEY_REFUSED}`);
}

function requiredSecret(options: Action1GatewayOptions | undefined, given: readonly unknown[]): string {
  const secret: unknown = options?.clientSecret;
  if (typeof secret !== 'string' || secret.trim() === '') {
    throw new GatewayConfigError(
      'createAction1Gateway requires options.clientSecret. Embedded instances do not read credentials from the environment.',
    );
  }
  // Key admission (src/key-admission.ts): printable ASCII of 16 characters or more, sharing no piece with any text of
  // ours. Checked before anything is built from it; the refusal is a fixed text that holds no piece of it.
  if (!admitsKey(secret.trim())) throw new GatewayConfigError(refusedText('options.clientSecret', given));
  return secret.trim();
}

/**
 * The client id: printable ASCII only. It is an identifier Action1 shows as an
 * e-mail-like text (it may share pieces with our own texts, such as the API
 * host name), so it is not held to key admission; it is redacted as a whole
 * value wherever it appears, and never quoted in an error.
 */
function requiredClientId(options: Action1GatewayOptions | undefined): string {
  const clientId: unknown = options?.clientId;
  if (typeof clientId !== 'string' || clientId.trim() === '') {
    throw new GatewayConfigError(
      'createAction1Gateway requires options.clientId. Embedded instances do not read credentials from the environment.',
    );
  }
  if (!CLIENT_ID.test(clientId.trim())) throw new GatewayConfigError('options.clientId was refused: it is not a printable API client id.');
  return clientId.trim();
}

function requiredRegion(options: Action1GatewayOptions | undefined): Action1Region {
  const region: unknown = options?.region;
  if (typeof region !== 'string' || !Object.hasOwn(ACTION1_REGIONS, region)) {
    throw new GatewayConfigError(`options.region must be one of ${ACTION1_REGION_IDS.join(', ')}.`);
  }
  return region as Action1Region;
}

/** A caller id from the host: redacted before it is cut short, so no part of a secret survives. */
function contextValue(value: unknown, redactor: SecretRedactor): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? redactor.redact(value.trim()).slice(0, 200) : undefined;
}

/**
 * A redactor that also replaces whole values: the client id, and access tokens Action1 issued that were dropped unused
 * (their pieces may be ordinary text, such as the Action1 host name or a fallback, so only the whole value is matched).
 */
class InstanceRedactor extends SecretRedactor {
  private readonly whole = new Set<string>();
  constructor(clientId: string) {
    super();
    this.addWhole(clientId);
  }
  addWhole(value: string): this {
    if (value.length >= 8) this.whole.add(value);
    return this;
  }
  override redact(value: string): string {
    let result = value;
    for (const whole of this.whole) result = result.split(whole).join(REDACTION_MARKER);
    return super.redact(result);
  }
  override matches(text: string): boolean {
    if (super.matches(text)) return true;
    for (const whole of this.whole) if (text.includes(whole)) return true;
    return false;
  }
}

/**
 * Create one gateway instance. `clientId`, `clientSecret` and `region` are
 * required and are the only connection settings the instance uses; a missing
 * or refused value fails here, before anything is built or sent.
 */
export function createAction1Gateway(options: Action1GatewayOptions) {
  let secret: string | undefined;
  let guard: InstanceRedactor | undefined;
  // What the host gave, admitted or not: every error is masked against it.
  const raw = options as Partial<Action1GatewayOptions> | undefined;
  const secrets = typeof raw?.clientSecret === 'string' ? [raw.clientSecret, raw.clientSecret.trim()] : [];
  try {
    const clientId = requiredClientId(options);
    secret = requiredSecret(options, secrets);
    guard = new InstanceRedactor(clientId);
    guard.addSecret(secret);
    // The fixed outputs of the sink check (src/fallbacks.ts) must hold no piece of the secret.
    if (leaksSecret(fixedOutputs(), guard)) throw new GatewayConfigError(refusedText('options', secrets));
    const gateway = buildAction1Gateway(options, clientId, secret, guard);
    // The tool list leaves the gateway as it is: a secret that shares a piece with it is refused.
    if (leaksSecret(gateway.tools, guard)) throw new GatewayConfigError(refusedText('options', secrets));
    return gateway;
  } catch (error) {
    let message = error instanceof Error ? error.message : String(error);
    if (guard && secret !== undefined) {
      message = guard.redact(message);
      if (leaksSecret(message, guard)) message = refusedText('options', secrets);
    }
    // A fresh error in final form (src/key-admission.ts, sealedError): no cause, a stack without frames, and name,
    // message and stack masked against the secret (no text of ours quotes the client id).
    const final = sealedError(new GatewayConfigError(message), ...secrets);
    if (guard && secret !== undefined && leaksSecret(final, guard)) {
      throw sealedError(new GatewayConfigError(refusedText('options', secrets)), ...secrets);
    }
    throw final;
  }
}

function buildAction1Gateway(options: Action1GatewayOptions, clientId: string, clientSecret: string, redactor: InstanceRedactor) {
  // Only these options are read; anything else a host passes is dropped.
  const { policy: hostPolicy, fetchImpl, timeoutMs } = options;
  const region = requiredRegion(options);
  if (fetchImpl !== undefined && typeof fetchImpl !== 'function') {
    throw new GatewayConfigError('options.fetchImpl must be a function.');
  }
  // Always a policy: the host's, or the default one. A gateway call never reads policy or audit variables.
  const policy: ResolvedInstancePolicy = resolveInstancePolicy(hostPolicy ?? {}, GATEWAY_TOOL_NAMES);
  const client = new Action1GatewayClient({
    clientId,
    clientSecret,
    region,
    timeoutMs: timeoutMs ?? DEFAULT_TIMEOUT_MS,
    redactor,
    redactWhole: value => void redactor.addWhole(value),
    ...(fetchImpl ? { fetchImpl } : {}),
  });
  const offeredTools: ReadonlySet<string> = new Set(GATEWAY_TOOL_NAMES.filter(name => !policy.disabledTools.has(name)));

  return {
    /** Tools enabled on this instance (tools the host's policy disables are left out). */
    tools: action1GatewayTools.filter(tool => !policy.disabledTools.has(canonicalToolName(tool.name))),
    callTool(toolName: string, input: GatewayJsonObject = {}, context?: GatewayCallContext): Promise<GatewayToolResult> {
      return runInCallScope(
        {
          policy,
          redactor,
          caller: contextValue(context?.caller, redactor),
          // Our own id for the call: the host's request id is its text, and is not written to the audit.
          requestId: randomUUID(),
          offeredTools,
        },
        () =>
          runCall(toolName, input).then(result => {
            const final = result.isError ? (redactDeep(result, redactor) as GatewayToolResult) : result;
            // The sink check, as the very last step: a result that holds a piece of a secret anywhere is withheld whole.
            return leaksSecret(final, redactor) ? withheldResult() : final;
          }),
      );
    },
  };

  async function runCall(toolName: string, input: GatewayJsonObject): Promise<GatewayToolResult> {
    try {
      const name = typeof toolName === 'string' ? canonicalToolName(toolName) : '';
      const tool = TOOLS_BY_NAME.get(name);
      if (!tool) {
        // Neither the audit record nor the answer repeats the name: it is the caller's text, not ours.
        await writeGatewayAuditEvent({ tool: UNKNOWN_TOOL, action: 'rejected', reason: 'unsupported tool' });
        return errorResult('Unsupported Action1 gateway tool.');
      }
      const parsed = tool.schema.safeParse(input ?? {});
      if (!parsed.success) {
        await writeGatewayAuditEvent({ tool: name, action: 'rejected', reason: 'invalid input' });
        return errorResult(redactText(`Invalid input for ${tool.name}: ${z.prettifyError(parsed.error)}`, redactor));
      }
      const data = await runGatewayTool(tool, client, parsed.data as Record<string, unknown>);
      return jsonResult(tool.summary, redactDeep(redactDeep(data, redactor), redactor));
    } catch (error) {
      return errorResult(redactText(error instanceof Error ? error.message : String(error), redactor));
    }
  }
}

/** The audit's tool for a call to a tool this gateway does not have. */
const UNKNOWN_TOOL = 'unknown_tool';

/** One gateway instance, as returned by createAction1Gateway. */
export type Action1Gateway = ReturnType<typeof createAction1Gateway>;

/**
 * The summary, then the same (already redacted) data as compact JSON in the text block, as the MCP spec asks of a
 * tool that returns structured content: many clients read only the text.
 */
function jsonResult(text: string, structuredContent: unknown): GatewayToolResult {
  const data = JSON.parse(JSON.stringify(structuredContent ?? null)) as GatewayJsonValue;
  return { content: [{ type: 'text', text: `${text}\n\n${JSON.stringify(data)}` }], structuredContent: data };
}

function errorResult(text: string): GatewayToolResult {
  return { isError: true, content: [{ type: 'text', text }] };
}
