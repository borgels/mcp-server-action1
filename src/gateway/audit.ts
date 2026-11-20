import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { withheldAuditRecord } from '../fallbacks.js';
import { leaksSecret } from '../key-admission.js';
import { redactDeep } from '../redaction.js';
import { currentCallContext, currentInstancePolicy, currentRedactor } from './scope.js';

export interface GatewayAuditEvent {
  tool: string;
  action: 'start' | 'finish' | 'error' | 'policy_denied' | 'rejected';
  target?: unknown;
  status?: string;
  reason?: string;
  error?: unknown;
}

/**
 * The audit's code for an error in a gateway call: the HTTP status of an
 * Action1 error, `timeout`, or `error`. Only codes from this fixed set are
 * written; the error's message never is.
 */
export function auditErrorCode(error: unknown): string {
  const status = (error as { status?: unknown } | null)?.status;
  if (error instanceof Error && error.name === 'Action1HttpError' && typeof status === 'number' && Number.isInteger(status)) {
    return `http_${status}`;
  }
  if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) return 'timeout';
  return 'error';
}

/** The key of the caller pseudonyms: random per process, never written anywhere. */
const CALLER_KEY = randomBytes(32);

/** The caller as `hmac:` and 16 hex characters: the same caller gives the same pseudonym within the process. */
export function callerPseudonym(caller: string | undefined): string | undefined {
  if (caller === undefined || caller === '') return undefined;
  return `hmac:${createHmac('sha256', CALLER_KEY).update(caller, 'utf8').digest('hex').slice(0, 16)}`;
}

/**
 * One audit record of a gateway call, to the host policy's `audit` sink (no-op
 * without one). No ACTION1_AUDIT_LOG is read. The caller is written only as a
 * pseudonym, the ids a call is about only as a hash, an error only as a fixed
 * code. A failing sink throws, so a tool whose start record cannot be written
 * does not run.
 */
export async function writeGatewayAuditEvent(event: GatewayAuditEvent): Promise<void> {
  const sink = currentInstancePolicy()?.audit;
  if (!sink) return;
  const context = currentCallContext();
  const record = {
    timestamp: new Date().toISOString(),
    requestId: context.requestId ?? randomUUID(),
    tool: event.tool,
    caller: callerPseudonym(context.caller),
    action: event.action,
    targetHash: event.target === undefined ? undefined : hashValue(JSON.stringify(event.target)),
    status: event.status,
    reason: event.reason,
    error: event.error === undefined ? undefined : auditErrorCode(event.error),
  };
  const redactor = currentRedactor();
  const safe = JSON.parse(JSON.stringify(redactDeep(redactDeep(record, redactor), redactor))) as Record<string, unknown>;
  // The sink check (src/key-admission.ts), on the record in its final form.
  await sink(redactor !== undefined && leaksSecret(safe, redactor) ? withheldAuditRecord() : safe);
}

function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
