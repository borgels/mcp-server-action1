/**
 * Failure metadata on gateway error results, in the shape of mcp-server-template's `failure`: the HTTP status Action1
 * answered with and Action1's own request id, for a host that counts failures without reading their text. Never the
 * response body, Action1's error code or message, or the input.
 */

/** Response headers that may carry Action1's id for a request, most specific first. */
export const REQUEST_ID_HEADERS: readonly string[] = [
  'x-request-id',
  'request-id',
  'x-correlation-id',
  'correlation-id',
  'x-amzn-requestid',
];

/**
 * A hex id: one run of hex digits, or groups of at least four hex digits joined by single hyphens (a UUID is one),
 * 8 to 64 characters in all. A name, a sentence or an e-mail address never fits.
 */
const REQUEST_ID_FORM = /^[0-9A-Fa-f]{4,}(?:-[0-9A-Fa-f]{4,})*$/;
/** Six digits and four more: the shape of a Danish personal number. An id that holds it is dropped. */
const PERSONAL_NUMBER_SHAPE = /\d{6}-?\d{4}/;

/** The request id only in the form such ids have (a UUID or a hex id of 8 to 64 characters), or undefined. */
export function vendorRequestId(value: string | null | undefined): string | undefined {
  if (typeof value !== 'string') return undefined;
  const id = value.trim();
  return id.length >= 8 && id.length <= 64 && REQUEST_ID_FORM.test(id) && !PERSONAL_NUMBER_SHAPE.test(id) ? id : undefined;
}

/** The request id from the first of REQUEST_ID_HEADERS a response has in the right form, or undefined. */
export function requestIdFrom(headers: Headers, names: readonly string[] = REQUEST_ID_HEADERS): string | undefined {
  for (const name of names) {
    const id = vendorRequestId(headers.get(name));
    if (id !== undefined) return id;
  }
  return undefined;
}

export interface FailureMetadata {
  /** The HTTP status of Action1's answer (100-599). */
  httpStatus: number;
  /** Action1's own id for the request, as a UUID or hex id only. */
  requestId?: string;
}

/** The failure metadata of an error: an HTTP error from Action1, or a refused redirect, gives its status and id. */
export function failureMetadata(error: unknown): FailureMetadata | undefined {
  if (!(error instanceof Error) || (error.name !== 'Action1HttpError' && error.name !== 'Action1RedirectError')) return undefined;
  const { status, requestId } = error as Error & { status?: unknown; requestId?: unknown };
  if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599) return undefined;
  const id = vendorRequestId(typeof requestId === 'string' ? requestId : undefined);
  return id === undefined ? { httpStatus: status } : { httpStatus: status, requestId: id };
}

/**
 * The failure metadata as it must be after redaction: on an error result only, a status of 100-599 and a request id
 * still in the form of one (redaction can have changed it). Anything else is dropped, never passed on.
 */
export function failureInForm(isError: boolean | undefined, failure: unknown): FailureMetadata | undefined {
  if (!isError || failure === null || typeof failure !== 'object') return undefined;
  const { httpStatus, requestId } = failure as { httpStatus?: unknown; requestId?: unknown };
  if (typeof httpStatus !== 'number' || !Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599) return undefined;
  const id = vendorRequestId(typeof requestId === 'string' ? requestId : undefined);
  return id === undefined ? { httpStatus } : { httpStatus, requestId: id };
}
