// The check's 10 s limit (DEADLINE_MS in src/dns/deadline.ts), for checkDomain and
// checkAlignment alike; deadline.test.ts pins deadline() on its own. On fake timers, with DNS that
// never answers until its signal aborts, so only the limit can end the wait.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkAlignment, checkDomain } from "../src/index.ts";
import { input } from "./helpers/check.ts";
import { silentOn, zoneResolver } from "./helpers/zone.ts";

const LIMIT_MS = 10_000;

// Every query waits for its signal, then fails as an aborted fetch does.
const silent = silentOn(zoneResolver({}), () => true);

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("the check's 10 s limit", () => {
  it("checkDomain waits for silent DNS until 10,000 ms, and stops there", async () => {
    let done = false;
    const report = checkDomain(input("example.com"), { resolver: silent }).then((r) => ((done = true), r));
    await vi.advanceTimersByTimeAsync(LIMIT_MS - 1);
    expect(done, "still checking at 9,999 ms").toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done, "ended by 10,000 ms").toBe(true);
    expect((await report).outcome).not.toBe("done");
  });

  it("checkAlignment waits for silent DNS until 10,000 ms, and stops there", async () => {
    let done = false;
    const result = checkAlignment(
      { fromDomain: "example.com", dkimDomains: ["example.com"] },
      { resolver: silent },
    ).then((r) => ((done = true), r));
    await vi.advanceTimersByTimeAsync(LIMIT_MS - 1);
    expect(done, "still looking up at 9,999 ms").toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done, "ended by 10,000 ms").toBe(true);
    await result;
  });
});
