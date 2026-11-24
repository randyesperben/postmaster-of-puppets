// spf-multiple-records through full checks: the record its fix merges from two, and the walk of
// that merged record. A merged record is no fix to copy when it would add a problem the starting
// records did not have.
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkDomain } from "../src/index.ts";
import type { Resolver } from "../src/dns/types.ts";
import type { Finding, Report } from "../src/types.ts";
import { bad, check, googleZone, input, P4, spfRange, stepThrough } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import { failing } from "./helpers/fixes.ts";
import { type Node, silentOn, type Zone, zoneResolver } from "./helpers/zone.ts";

/** The spf-multiple-records finding of a report. */
const spfFinding = (r: Report) => r.findings.find((x) => x.id === "spf-multiple-records") as Report["findings"][number];
/** Case A with these records as example.com's TXT. */
const twoSpf = (records: string[], extra: Zone = {}): Zone => {
  const z = { ...googleZone(), ...extra };
  (z["example.com"] as Node).TXT = records;
  return z;
};

describe("merging two SPF records", () => {
  it("two SPF records merge into one, in order, with the stricter all", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com ~all", "v=spf1 include:sendgrid.net -all"];
    z["sendgrid.net"] = spfRange();
    const f = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(f.fixes.map((x) => [x.action, x.host, x.value])).toEqual([
      ["replace", "@", "v=spf1 include:_spf.google.com include:sendgrid.net -all"],
      ["remove", "@", "v=spf1 include:sendgrid.net -all"],
    ]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });

  // RFC 7208 §6.1 ignores redirect when the record has an all, so a redirect carried into a merged
  // record with an all loses its sender. It becomes an include before the all; a redirect its own
  // record already ignored stays out.
  it("two SPF records, one a redirect: the redirect becomes an include before the all", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 redirect=_spf.provider.example.net", "v=spf1 ip4:192.0.32.10 -all"];
    z["_spf.provider.example.net"] = spfRange();
    const f = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(f.fixes[0]?.value).toBe("v=spf1 ip4:192.0.32.10 include:_spf.provider.example.net -all");
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
    expect((after as Report).spf.record).toBe("v=spf1 ip4:192.0.32.10 include:_spf.provider.example.net -all");
  });

  it("two SPF records, a redirect in a record that has an all: §6.1 already ignored it, so it stays out", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = [
      "v=spf1 include:_spf.google.com redirect=_spf.provider.example.net ~all",
      "v=spf1 ip4:192.0.32.10 -all",
    ];
    const f = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(f.fixes[0]?.value).toBe("v=spf1 include:_spf.google.com ip4:192.0.32.10 -all");
  });

  // Neither record has an all.
  it("two SPF records, both redirects: the first stays the redirect, the second becomes an include", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 redirect=_spf.google.com", "v=spf1 redirect=_spf.provider.example.net"];
    z["_spf.provider.example.net"] = spfRange();
    const f = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(f.fixes[0]?.value).toBe("v=spf1 include:_spf.provider.example.net redirect=_spf.google.com");
    (z["example.com"] as Node).TXT = ["v=spf1 redirect=_spf.google.com", "v=spf1 redirect=_SPF.google.com"];
    const same = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(same.fixes[0]?.value).toBe("v=spf1 redirect=_spf.google.com");
  });

  it("merging two SPF records keeps a shared include once", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = [
      "v=spf1 include:_spf.google.com ~all",
      "v=spf1 include:_spf.google.com include:sendgrid.net ~all",
    ];
    z["sendgrid.net"] = spfRange();
    const f = (await check(z)).findings.find((x) => x.id === "spf-multiple-records") as Finding;
    expect(f.fixes[0]?.value).toBe("v=spf1 include:_spf.google.com include:sendgrid.net ~all");
  });

  // RFC 7208 §5.1, “Mechanisms listed after "all" MUST be ignored”: what follows an all
  // never counted, so it stays out of the merged record instead of moving before the new all.
  it("each record is cut at its first all before the merge", async () => {
    const z = twoSpf(["v=spf1 ip4:192.0.32.10 -all ip4:0.0.0.0/1", "v=spf1 ip4:192.0.32.11 -all"]);
    const f = spfFinding(await check(z));
    expect(f.fixes[0]?.value).toBe("v=spf1 ip4:192.0.32.10 ip4:192.0.32.11 -all");
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
    expect(after?.verdict).toBe("protected");
  });

  // The redirect modifier's name is case-insensitive (RFC 7208 §12, ABNF strings).
  it("REDIRECT= in capitals becomes an include before the all, as redirect= does", async () => {
    const z = twoSpf(["v=spf1 REDIRECT=_spf.provider.example.net", "v=spf1 ip4:192.0.32.10 -all"], {
      "_spf.provider.example.net": spfRange(),
    });
    const f = spfFinding(await check(z));
    expect(f.fixes[0]?.value).toBe("v=spf1 ip4:192.0.32.10 include:_spf.provider.example.net -all");
  });

  // A fix adds no critical or warning: a merged record that a receiver would reject (more than 10
  // lookups, a loop back to the domain, an empty redirect) is no record to copy. The finding keeps
  // its steps, with no copyable fix.
  it.each([
    [
      "more than 10 lookups once merged",
      [
        "v=spf1 redirect=_spf.provider.example.net",
        "v=spf1 a:a1.example.net a:a2.example.net a:a3.example.net a:a4.example.net a:a5.example.net -all",
      ],
      {
        "_spf.provider.example.net": {
          TXT: ["v=spf1 a:b1.example.net a:b2.example.net a:b3.example.net a:b4.example.net a:b5.example.net -all"],
        },
        ...Object.fromEntries(
          ["a1", "a2", "a3", "a4", "a5", "b1", "b2", "b3", "b4", "b5"].map((h) => [`${h}.example.net`, { A: [P4] }]),
        ),
      },
    ],
    ["a redirect back to the domain itself", ["v=spf1 redirect=example.com", `v=spf1 ip4:${P4} -all`], {}],
    ["an empty redirect", ["v=spf1 redirect=", `v=spf1 ip4:${P4} -all`], {}],
  ] as const)("%s: no copyable fix, only the steps", async (_, records, extra) => {
    const f = spfFinding(await check(twoSpf([...records], extra as Zone)));
    expect(f.fixes).toEqual([]);
  });
});

// The walk of the merged record, and the rule that its fix adds no problem the starting records
// did not have.
describe("the merged SPF record of spf-multiple-records", () => {
  afterEach(() => vi.useRealTimers());

  // No receiver makes these lookups (§4.5: two records are a permerror), so a silent
  // include in the merged record must not hold the check to its 10 s limit and mark it partial.
  // Done, not partial.
  it("a silent include in the merged record: the check is done, and the merge has no fix to copy", async () => {
    vi.useFakeTimers();
    const z = twoSpf(["v=spf1 include:_spf.google.com -all", "v=spf1 include:slow.example.net -all"]);
    const t0 = Date.now();
    let doneAt = -1;
    const p = checkDomain(input("example.com"), {
      resolver: silentOn(zoneResolver(z), (n) => n === "slow.example.net"),
    }).then((r) => ((doneAt = Date.now() - t0), r));
    await vi.advanceTimersByTimeAsync(11_000);
    const r = await p;
    expect(r.outcome).toBe("done");
    expect(doneAt).toBeLessThan(10_000);
    expect(spfFinding(r).fixes).toEqual([]);
  });

  // The cleaned record of an open SPF is walked with the merge's time limit, and a walk that does
  // not finish leaves no fix to copy. The include answers the first walk and then goes silent, so
  // only the walk of the cleaned record waits for it.
  it("an include silent for the walk of an open SPF's cleaned record: no fix to copy, check done", async () => {
    vi.useFakeTimers();
    const z = twoSpf(["v=spf1 ip4:0.0.0.0/0 include:slow.example.net ~all"], {
      "slow.example.net": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    });
    const inner = zoneResolver(z);
    const silent = silentOn(inner, (n) => n === "slow.example.net");
    let asked = false;
    const once: Resolver = {
      query: (name, type, opts) => {
        const slow = name.replace(/\.$/, "").toLowerCase() === "slow.example.net";
        if (slow && asked) return silent.query(name, type, opts);
        asked ||= slow;
        return inner.query(name, type, opts);
      },
    };
    const t0 = Date.now();
    let doneAt = -1;
    const p = checkDomain(input("example.com"), { resolver: once }).then((r) => ((doneAt = Date.now() - t0), r));
    await vi.advanceTimersByTimeAsync(11_000);
    const r = await p;
    expect(r.outcome).toBe("done");
    expect(doneAt).toBeLessThan(10_000);
    expect(r.findings.filter((f) => f.id === "spf-open-range").map((f) => f.fixes)).toEqual([[]]);
    // Answered, the same cleaned record is the fix.
    expect((await check(z)).findings.find((f) => f.id === "spf-open-range")?.fixes[0]?.value).toBe(
      "v=spf1 include:slow.example.net ~all",
    );
  });

  // The check's own 10 s can cut the walk of the cleaned record (or of the merge) before that
  // walk's 3 s are up, so its own timer never fires. A walk the check cut did not finish either: no
  // fix to copy, and the result is partial.
  const lateThenSilent = (inner: Resolver, late: string, ms: number): Resolver => {
    const silent = silentOn(inner, (n) => n === late);
    let asked = false;
    return {
      query: (name, type, opts) => {
        if (name.replace(/\.$/, "").toLowerCase() !== late) return inner.query(name, type, opts);
        if (asked) return silent.query(name, type, opts);
        asked = true;
        return new Promise((res) => setTimeout(res, ms)).then(() => inner.query(name, type, opts));
      },
    };
  };

  it("the check's limit cuts the walk of the cleaned record of an open SPF: no fix to copy", async () => {
    vi.useFakeTimers();
    const z = twoSpf(["v=spf1 ip4:0.0.0.0/0 include:slow.example.net ~all"], {
      "slow.example.net": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    });
    const p = checkDomain(input("example.com"), {
      resolver: lateThenSilent(zoneResolver(z), "slow.example.net", 7_500),
    });
    await vi.advanceTimersByTimeAsync(11_000);
    const r = await p;
    expect(r.outcome).toBe("partial");
    expect(r.findings.filter((f) => f.id === "spf-open-range").map((f) => f.fixes)).toEqual([[]]);
  });

  // RFC 7208 §5.1 ignores mechanisms after all, not modifiers; §6 puts exp at the end.
  it("an exp= after the all stays in the merged record", async () => {
    const z = twoSpf(["v=spf1 ip4:192.0.32.10 -all exp=explain.example.net", "v=spf1 ip4:192.0.32.11 -all"]);
    expect(spfFinding(await check(z)).fixes[0]?.value).toBe(
      "v=spf1 ip4:192.0.32.10 ip4:192.0.32.11 -all exp=explain.example.net",
    );
  });

  // With no all in either record, the merged one has none either, so its spf-neutral-all
  // (hardening) is no new problem: the fix stays.
  it("two records with no all: the merge keeps its fix, and spf-neutral-all after it is no new problem", async () => {
    const z = twoSpf(["v=spf1 include:_spf.google.com", "v=spf1 ip4:192.0.32.11"]);
    const f = spfFinding(await check(z));
    expect(f.fixes[0]?.value).toBe("v=spf1 include:_spf.google.com ip4:192.0.32.11");
    const [after] = await stepThrough(z, f);
    expect(ids(after as Report)).toContain("spf-neutral-all");
    expect(bad(after as Report).filter((id) => id !== "spf-neutral-all")).toEqual([]);
  });

  // A warning past hardening in the merged walk (an include with no answer) takes the fix away, as
  // a critical does.
  it("an include of the merged record without an answer: no fix to copy", async () => {
    const z = twoSpf(["v=spf1 include:_spf.google.com -all", "v=spf1 include:dead.example.net -all"]);
    const r = await checkDomain(input("example.com"), { resolver: failing(z, ["dead.example.net TXT"]) });
    expect(spfFinding(r).fixes).toEqual([]);
  });
});
