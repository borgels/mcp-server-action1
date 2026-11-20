/**
 * The fixed outputs of the sink check (src/key-admission.ts): what leaves a
 * gateway instead of an output that holds a piece of the key. A small closed
 * set; a key that shares a piece with any of them is refused when the
 * gateway is created, so a fallback never holds a piece of the key.
 */

/** The text of a result that was withheld. */
export const RESULT_WITHHELD = 'Withheld: the answer held text that matches a credential of this instance.';

/** The result a host gets instead of one that held a piece of the key. */
export function withheldResult(): { isError: true; content: Array<{ type: 'text'; text: string }> } {
  return { isError: true, content: [{ type: 'text', text: RESULT_WITHHELD }] };
}

/** The audit record written instead of one that held a piece of the key. */
export function withheldAuditRecord(): Record<string, unknown> {
  return { auditRecord: 'withheld' };
}

/** Names a host may log with a refusal: the error classes a gateway throws. */
const ERROR_NAMES = ['GatewayConfigError', 'Error'];

/** Every fixed output, as a host or a log sees it. */
export function fixedOutputs(): unknown[] {
  return [withheldResult(), withheldAuditRecord(), `${JSON.stringify(withheldAuditRecord())}\n`, ...ERROR_NAMES];
}
