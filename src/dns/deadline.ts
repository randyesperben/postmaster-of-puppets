// The time limit of a check: one signal that aborts every lookup in flight when the time runs out
// or the caller's signal aborts.

/** The check's time limit, for checkDomain and checkAlignment alike. */
const DEADLINE_MS = 10_000;

/**
 * The check's own signal: aborts at ms (DEADLINE_MS when undefined) or when the caller's signal
 * aborts, whichever comes first. dispose() clears the timer.
 */
export function deadline(
  ms: number = DEADLINE_MS,
  parent?: AbortSignal,
): { signal: AbortSignal; expired(): boolean; dispose(): void } {
  const ctrl = new AbortController();
  let expired = false;
  const timer = setTimeout(() => {
    expired = true;
    ctrl.abort();
  }, ms);
  const onAbort = (): void => ctrl.abort();
  if (parent?.aborted) ctrl.abort();
  else parent?.addEventListener("abort", onAbort, { once: true });
  return {
    signal: ctrl.signal,
    expired: () => expired,
    dispose() {
      clearTimeout(timer);
      parent?.removeEventListener("abort", onAbort);
    },
  };
}
