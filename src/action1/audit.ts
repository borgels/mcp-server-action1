import { createHash, randomUUID } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { formatUnknownError } from '../errors.js';

export interface Action1AuditEvent {
  requestId?: string;
  tool: string;
  action: 'start' | 'finish' | 'error' | 'policy_denied';
  target?: unknown;
  status?: string;
  reason?: string;
  error?: unknown;
}

export async function writeAuditEvent(event: Action1AuditEvent): Promise<void> {
  const auditPath = process.env.ACTION1_AUDIT_LOG;
  if (!auditPath) {
    return;
  }

  const record = {
    timestamp: new Date().toISOString(),
    requestId: event.requestId ?? randomUUID(),
    tool: event.tool,
    action: event.action,
    targetHash: event.target === undefined ? undefined : hashValue(JSON.stringify(event.target)),
    status: event.status,
    reason: event.reason,
    error: event.error === undefined ? undefined : formatUnknownError(event.error),
  };

  await appendFile(auditPath, `${JSON.stringify(record)}\n`, 'utf8');
}

function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
