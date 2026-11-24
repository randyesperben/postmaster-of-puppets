// dns/deadline.ts: the check's time limit, which aborts at its time or with its parent signal.
import { afterEach, describe, expect, it, vi } from "vitest";
import { deadline } from "../src/dns/deadline.ts";

const LIMIT_MS = 10_000;

describe("deadline()", () => {
  afterEach(() => vi.useRealTimers());

  it("deadline() aborts at 10,000 ms, not at 9,999", () => {
    vi.useFakeTimers();
    const limit = deadline();
    vi.advanceTimersByTime(LIMIT_MS - 1);
    expect(limit.signal.aborted).toBe(false);
    expect(limit.expired()).toBe(false);
    vi.advanceTimersByTime(1);
    expect(limit.signal.aborted).toBe(true);
    expect(limit.expired()).toBe(true);
    limit.dispose();
  });

  it("deadline() aborts at its time or with its parent, and says which", async () => {
    const d = deadline(10);
    await new Promise((r) => setTimeout(r, 30));
    expect(d.signal.aborted).toBe(true);
    expect(d.expired()).toBe(true);
    d.dispose();

    const parent = new AbortController();
    const e = deadline(10_000, parent.signal);
    parent.abort();
    expect(e.signal.aborted).toBe(true);
    expect(e.expired()).toBe(false);
    e.dispose();

    const gone = new AbortController();
    gone.abort();
    const g = deadline(10_000, gone.signal);
    expect(g.signal.aborted).toBe(true);
    g.dispose();
  });
});
