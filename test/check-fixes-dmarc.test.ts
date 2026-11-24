// The DMARC fixes, through full checks: each chain, applied back to the zone step by step, ends
// with its finding gone and no critical or warning added, and never asks less than the current
// record.
import { describe, expect, it } from "vitest";
import { catalog, fixesAsText } from "../src/index.ts";
import type { Finding, Report } from "../src/types.ts";
import {
  bad,
  check,
  DKIM,
  expectNoStepLowers,
  googleZone,
  inheritingShop,
  P4,
  RUA,
  SOA,
  stepThrough,
} from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

describe("DMARC fixes", () => {
  it("a no-mail domain already at reject with reports gets nothing", async () => {
    const r = await check({
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] },
      "*._domainkey.example.com": { TXT: ["v=DKIM1; p="] },
    });
    expect(r.verdict).toBe("protected");
    expect(r.findings.flatMap((f) => f.fixes)).toEqual([]);
  });

  it("a null MX on a domain that sends through a service: DMARC by steps, never reject at once", async () => {
    const z = googleZone();
    (z["example.com"] as Node).MX = ["0 ."];
    delete z["google._domainkey.example.com"];
    delete z["_dmarc.example.com"];
    const r = await check(z);
    // The SPF include authorizes Google: a null MX with signs of sending (RFC 7505 §4.2).
    expect(r.mailUse).toBe("mail");
    expect(r.delivery).toBe("at-risk");
    expect(r.findings.find((f) => f.id === "mx-null")).toMatchObject({
      severity: "warning",
      vars: { sending: 1 },
      fixes: [],
    });
    const values = r.findings.flatMap((f) => f.fixes.map((x) => x.value));
    expect(values).not.toContain("v=DMARC1; p=reject");
    expect(values[0]).toBe("v=DMARC1; p=none; rua=mailto:{rua}");
  });

  const withoutDmarc = (): Zone => {
    const z = googleZone();
    delete z["_dmarc.example.com"];
    return z;
  };

  it("DMARC missing: three steps, the expected findings after each", async () => {
    const before = await check(withoutDmarc());
    const f = before.findings.find((x) => x.id === "dmarc-missing") as Finding;
    // prettier-ignore
    expect(f.fixes.map((x) => [x.action, x.host, x.name, x.value, x.step])).toEqual([
      ["add",     "_dmarc", "_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:{rua}",
        { n: 1, of: 3, protects: false }],
      ["replace", "_dmarc", "_dmarc.example.com", "v=DMARC1; p=quarantine; rua=mailto:{rua}",
        { n: 2, of: 3, protects: true }],
      ["replace", "_dmarc", "_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:{rua}",
        { n: 3, of: 3, protects: true }],
    ]);
    const [one, two, three] = await stepThrough(withoutDmarc(), f);
    expect(bad(one as Report)).toEqual(["dmarc-policy-none"]);
    expect(bad(two as Report)).toEqual(["dmarc-policy-quarantine"]);
    expect(bad(three as Report)).toEqual([]);
    expect(three?.verdict).toBe("protected");
  });

  it("DMARC at none with reports already: steps 2 and 3 of 3", async () => {
    const z = googleZone(`v=DMARC1; p=none; rua=mailto:${RUA}`);
    const f = (await check(z)).findings.find((x) => x.id === "dmarc-policy-none") as Finding;
    expect(f.fixes.map((x) => x.step?.n)).toEqual([2, 3]);
    const after = await stepThrough(z, f);
    expect(after.map(bad)).toEqual([["dmarc-policy-quarantine"], []]);
  });

  // With pct from 1 to 99 the first step must not swap pct for t=y: that would lower by one level
  // what RFC 9989 receivers are asked, since they read no pct (§4.7 and Appendix C.5.2). No step
  // asks less than either reading applies to the current record (readings in helpers/check.ts).
  it.each([
    [
      `v=DMARC1; p=quarantine; pct=25; rua=mailto:${RUA}`,
      [`v=DMARC1; p=quarantine; rua=mailto:${RUA}`, `v=DMARC1; p=reject; rua=mailto:${RUA}`],
      [["dmarc-policy-quarantine"], []],
    ],
    [`v=DMARC1; p=reject; pct=50; rua=mailto:${RUA}`, [`v=DMARC1; p=reject; rua=mailto:${RUA}`], [[]]],
  ])("pct below 100 on %j: no t=y, and no step asks less than the current record", async (record, values, after) => {
    const z = googleZone(record);
    const r = await check(z);
    const f = r.findings.find((x) => x.fixes.length > 0 && x.group === "dmarc") as Finding;
    expect(f.fixes.map((x) => x.value)).toEqual(values);
    const steps = await stepThrough(z, f);
    expect(steps.map(bad)).toEqual(after);
    expectNoStepLowers(r, steps);
  });

  it("subdomains open with sp=none: two steps, sp=quarantine and then without sp", async () => {
    const z = googleZone(`v=DMARC1; p=reject; sp=none; np=none; rua=mailto:${RUA}`);
    const f = (await check(z)).findings.find((x) => x.id === "dmarc-subdomains-open") as Finding;
    expect(f.fixes.map((x) => [x.value, x.step])).toEqual([
      [`v=DMARC1; p=reject; sp=quarantine; rua=mailto:${RUA}`, { n: 1, of: 2, protects: true }],
      [`v=DMARC1; p=reject; rua=mailto:${RUA}`, { n: 2, of: 2, protects: true }],
    ]);
    const [one, two] = await stepThrough(z, f);
    expect(one?.verdict).toBe("protected");
    expect(bad(two as Report)).toEqual([]);
    expect(fixesAsText(await check(z))).toContain(
      "Step 1 of 2. Receivers are now asked to quarantine mail from subdomains that fails DMARC. Your reports show which subdomains send mail: check them before step 2.",
    );
  });

  it("subdomains open with np=none only: one fix that drops np, no steps", async () => {
    const z = googleZone(`v=DMARC1; p=reject; np=none; rua=mailto:${RUA}`);
    const f = (await check(z)).findings.find((x) => x.id === "dmarc-subdomains-open") as Finding;
    expect(f.fixes.map((x) => [x.value, x.step])).toEqual([[`v=DMARC1; p=reject; rua=mailto:${RUA}`, undefined]]);
  });

  it("an inherited policy: steps on a record of the name's own, never the parent's record", async () => {
    for (const parent of [
      `v=DMARC1; p=reject; sp=none; rua=mailto:${RUA}`,
      `v=DMARC1; p=none; sp=none; rua=mailto:${RUA}`,
    ]) {
      const z = inheritingShop(parent);
      const r = await check(z, "shop.example.com");
      expect(r.verdict, parent).toBe("spoofable");
      const fixes = r.findings.flatMap((f) => f.fixes);
      expect(
        fixes.filter((x) => x.name === "_dmarc.example.com"),
        parent,
      ).toEqual([]);
      expect(
        fixes.map((x) => [x.action, x.name, x.value, x.step]),
        parent,
      ).toEqual([
        [
          "add",
          "_dmarc.shop.example.com",
          `v=DMARC1; p=quarantine; rua=mailto:${RUA}`,
          { n: 2, of: 3, protects: true },
        ],
        [
          "replace",
          "_dmarc.shop.example.com",
          `v=DMARC1; p=reject; rua=mailto:${RUA}`,
          { n: 3, of: 3, protects: true },
        ],
      ]);
      const f = r.findings.find((x) => x.fixes.length > 0) as Finding;
      const [two, three] = await stepThrough(z, f, "shop.example.com");
      expect(two?.verdict, parent).toBe("partly-protected");
      // shop's own policy is reject now; its subdomains still follow example.com's sp=none
      // (RFC 9989 §4.7), which is example.com's record to change, not this name's.
      expect(bad(three as Report), parent).toEqual(["dmarc-subdomains-open"]);
      expect(three?.dmarc.foundAt, parent).toBe("shop.example.com");
    }
  });

  it("a name without mail that inherits reject: no DMARC record of its own to add", async () => {
    const z: Zone = {
      "example.com": { SOA },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      "shop.example.com": { MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "*._domainkey.shop.example.com": { TXT: ["v=DKIM1; p="] },
    };
    const r = await check(z, "shop.example.com");
    expect(r.mailUse).toBe("none-declared");
    expect(r.verdict).toBe("protected");
    expect(r.findings.flatMap((f) => f.fixes).filter((x) => x.name.startsWith("_dmarc."))).toEqual([]);
  });

  it("an inherited quarantine moves to reject on the name's own record, keeping the parent's other tags", async () => {
    const z = inheritingShop(`v=DMARC1; p=reject; sp=quarantine; adkim=s; rua=mailto:${RUA}`);
    const r = await check(z, "shop.example.com");
    const fixes = r.findings.flatMap((f) => f.fixes);
    expect(fixes.map((x) => [x.action, x.name, x.value, x.step])).toEqual([
      ["add", "_dmarc.shop.example.com", `v=DMARC1; p=reject; adkim=s; rua=mailto:${RUA}`, undefined],
    ]);
  });

  // The full check loads the real Public Suffix List, so the case needs a real rule
  // (up.railway.app); the record at railway.app is made up. The step writes a record of the name's
  // own at reject, with the owner's rua; up.railway.app is a public suffix.
  it("dmarc-org-differs under up.railway.app: one step, the name's own record at reject", async () => {
    const d = "myapp.up.railway.app";
    const z: Zone = {
      "railway.app": { SOA },
      "_dmarc.railway.app": { TXT: ["v=DMARC1; p=reject; rua=mailto:dmarc@railway.example"] },
      [d]: { MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
      "smtp.google.com": { A: [P4] },
      "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
      [`google._domainkey.${d}`]: { TXT: [DKIM] },
    };
    const r = await check(z, d);
    expect(r.verdict).toBe("spoofable");
    const f = r.findings.find((x) => x.id === "dmarc-org-differs") as Finding;
    expect(f.fixes.map((x) => [x.action, x.name, x.value, x.step])).toEqual([
      ["add", `_dmarc.${d}`, "v=DMARC1; p=reject; rua=mailto:{rua}", undefined],
    ]);
    const [after] = await stepThrough(z, f, d);
    expect(after?.verdict).toBe("protected");
    expect(ids(after as Report)).not.toContain("dmarc-org-differs");
  });

  // The cause names that record and carries weaker.
  it("a second record only RFC 7489 reads (V=DMARC1): Spoofable, and the fix removes it", async () => {
    const z = googleZone(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
    (z["_dmarc.example.com"] as Node).TXT = [`v=DMARC1; p=reject; rua=mailto:${RUA}`, "V=DMARC1; p=none"];
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(r.groups.dmarc).not.toBe("pass");
    const f = r.findings.find((x) => x.id === "dmarc-multiple-records") as Finding;
    expect(f).toMatchObject({ severity: "critical", vars: { weaker: 1 } });
    expect(f.fixes.map((x) => [x.action, x.name, x.value])).toEqual([
      ["remove", "_dmarc.example.com", "V=DMARC1; p=none"],
    ]);
    const [after] = await stepThrough(z, f);
    expect(after?.verdict).toBe("protected");
    expect(bad(after as Report)).toEqual([]);
  });

  // The cause carries at for the parent.
  it("the same second record at the parent: the cause names it, the fix is the name's own record", async () => {
    const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
    (z["_dmarc.example.com"] as Node).TXT = [`v=DMARC1; p=reject; rua=mailto:${RUA}`, "V=DMARC1; p=none"];
    const r = await check(z, "shop.example.com");
    expect(r.verdict).toBe("spoofable");
    const f = r.findings.find((x) => x.id === "dmarc-multiple-records") as Finding;
    expect(f).toMatchObject({ severity: "critical", vars: { at: "example.com", weaker: 1 } });
    expect(f.fixes.map((x) => [x.action, x.name, x.value])).toEqual([
      ["add", "_dmarc.shop.example.com", `v=DMARC1; p=reject; rua=mailto:${RUA}`],
    ]);
    const [after] = await stepThrough(z, f, "shop.example.com");
    expect(after?.verdict).toBe("protected");
  });

  // shop.example.com's own sp or np opens its subdomains for RFC 9989, and with nothing at
  // example.com they are open for RFC 7489 too. The finding gives each reading its own policy, its
  // steps close the RFC 9989 part, and the record its text asks for at example.com closes the rest.
  for (const tags of ["sp=none", "np=none"]) {
    // shop is shop.example.com. The steps include the record at example.com, and applying them
    // closes the finding.
    it(`shop at p=reject; ${tags}, nothing at example.com: both causes, the steps close it`, async () => {
      const z = inheritingShop("");
      delete z["_dmarc.example.com"];
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; ${tags}; rua=mailto:${RUA}`] };
      const r = await check(z, "shop.example.com");
      const f = r.findings.find((x) => x.id === "dmarc-subdomains-open") as Finding;
      const sp = tags === "sp=none" ? "none" : "reject";
      expect(f.vars).toEqual({
        sp,
        np: "none",
        at: "shop.example.com",
        pslOrgDomain: "example.com",
        pslMissing: 1,
        both: 1,
      });
      expect(f.fixes.length).toBeGreaterThan(0);
      const after = (await stepThrough(z, f, "shop.example.com")).at(-1) as Report;
      const left = after.findings.find((x) => x.id === "dmarc-subdomains-open");
      expect(left?.vars).toEqual({
        sp: "reject",
        np: "reject",
        at: "shop.example.com",
        pslOrgDomain: "example.com",
        pslMissing: 1,
        weaker: 1,
      });
      expect(left?.fixes).toEqual([]);
      // What the fix text asks at _dmarc.{pslOrgDomain}: sp=reject, with a p= of its own there.
      const done: Zone = structuredClone(z);
      done["_dmarc.shop.example.com"] = { TXT: [(f.fixes.at(-1)?.value ?? "").split("{rua}").join(RUA)] };
      done["_dmarc.example.com"] = { TXT: [`v=DMARC1; p=none; sp=reject; rua=mailto:${RUA}`] };
      const closed = await check(done, "shop.example.com");
      expect(ids(closed)).not.toContain("dmarc-subdomains-open");
      expect(closed.verdict).toBe("protected");
    });
  }

  // example.com's record decides for the subdomains of shop.example.com (RFC 9989 §4.7: sp and np
  // count only at the Organizational Domain), so a step on shop's own record cannot close them. No
  // copyable step; the text names the record at _dmarc.{at}.
  // shop.example.com's record gets no step, and the finding's text names _dmarc.example.com.
  it("shop at p=reject; np=none under example.com at p=none: no step on shop's record", async () => {
    const z = inheritingShop(`v=DMARC1; p=none; rua=mailto:${RUA}`);
    z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; np=none; rua=mailto:${RUA}`] };
    const r = await check(z, "shop.example.com");
    const f = r.findings.find((x) => x.id === "dmarc-subdomains-open") as Finding;
    expect(f.vars).toMatchObject({ at: "example.com" });
    // Every copyable step closes what it is for: here there is none to take.
    expect(f.fixes).toEqual([]);
    expect(r.findings.flatMap((x) => x.fixes).filter((x) => x.name === "_dmarc.shop.example.com")).toEqual([]);
    expect(catalog.find((e) => e.id === "dmarc-subdomains-open")?.fix).toContain("in the DMARC record of {at}");
  });

  // Removing sp= and np= from example.com at p=none leaves them open, so no text offers it; setting
  // them to reject closes the finding.
  it("the fix text sets sp= and np= to reject at {at}, and that closes the finding", async () => {
    const entry = catalog.find((e) => e.id === "dmarc-subdomains-open");
    for (const fix of [entry?.fix, ...(entry?.variants ?? []).map((v) => v.fix)])
      expect(fix ?? "").not.toContain("remove them");
    const z = inheritingShop(`v=DMARC1; p=none; sp=reject; np=reject; rua=mailto:${RUA}`);
    z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; np=none; rua=mailto:${RUA}`] };
    const r = await check(z, "shop.example.com");
    expect(ids(r)).not.toContain("dmarc-subdomains-open");
    expect(r.verdict).toBe("protected");
  });

  // The subdomains' finding with no step on shop's record goes first; the missing rua on that
  // record still gets its copyable fix, and the fix closes it.
  it("shop.example.com without rua under example.com at p=none: dmarc-no-rua fixes shop's record", async () => {
    const z = inheritingShop(`v=DMARC1; p=none; rua=mailto:${RUA}`);
    z["_dmarc.shop.example.com"] = { TXT: ["v=DMARC1; p=reject; np=none"] };
    const r = await check(z, "shop.example.com");
    const f = r.findings.find((x) => x.id === "dmarc-no-rua") as Finding;
    expect(f.fixes.map((x) => [x.action, x.name, x.value])).toEqual([
      ["replace", "_dmarc.shop.example.com", "v=DMARC1; p=reject; np=none; rua=mailto:{rua}"],
    ]);
    const [after] = await stepThrough(z, f, "shop.example.com");
    expect(ids(after as Report)).not.toContain("dmarc-no-rua");
    expect((r.findings.find((x) => x.id === "dmarc-subdomains-open") as Finding).fixes).toEqual([]);
  });

  // The fix never restarts the chain at none.
  it("a mistyped record RFC 7489 reads: one replace with the corrected record", async () => {
    const cases: [string, string][] = [
      [`V=DMARC1; p=reject; rua=mailto:${RUA}`, `v=DMARC1; p=reject; rua=mailto:${RUA}`],
      [`v=DMARC1; p=reject; p=reject; rua=mailto:${RUA}`, `v=DMARC1; p=reject; rua=mailto:${RUA}`],
      [`v=DMARC1; P=reject; rua=mailto:${RUA}`, `v=DMARC1; p=reject; rua=mailto:${RUA}`],
    ];
    for (const [record, fixed] of cases) {
      const z = googleZone(record);
      const r = await check(z);
      const dmarc = r.findings.filter((f) => f.group === "dmarc" && f.fixes.length > 0);
      expect(
        dmarc.flatMap((f) => f.fixes.map((x) => [x.action, x.value, x.replaces, x.step])),
        record,
      ).toEqual([["replace", fixed, record, undefined]]);
      const [after] = await stepThrough(z, dmarc[0] as Finding);
      expect(after?.verdict, record).toBe("protected");
    }
  });

  it("a repeated tag with two values stays unreadable: the steps from none", async () => {
    const r = await check(googleZone(`v=DMARC1; p=reject; p=none; rua=mailto:${RUA}`));
    const fixes = r.findings.flatMap((f) => f.fixes).filter((x) => x.name === "_dmarc.example.com");
    expect(fixes[0]?.value).toBe(`v=DMARC1; p=none; rua=mailto:${RUA}`);
  });
});

// dmarc-no-rua and dmarc-policy-quarantine, however the record in force is written.
describe("DMARC fixes on the record as written", () => {
  it("no rua on a protected domain: a fix that adds it", async () => {
    const z = googleZone("v=DMARC1; p=reject");
    const f = (await check(z)).findings.find((x) => x.id === "dmarc-no-rua") as Finding;
    expect(f.fixes.map((x) => x.value)).toEqual(["v=DMARC1; p=reject; rua=mailto:{rua}"]);
    const [after] = await stepThrough(z, f);
    expect(ids(after as Report)).not.toContain("dmarc-no-rua");
    expect(bad(after as Report)).toEqual([]);
  });

  // The record in force must match the chain's value however it is written: compared as published
  // (“v=DMARC1; p=reject;”) with a value written without the final semicolon, the fix would
  // replace it with the same record and no rua.
  it.each(["v=DMARC1; p=reject;", "v=DMARC1;p=reject"])(
    "dmarc-no-rua on %j adds rua and nothing else",
    async (record) => {
      const z = googleZone(record);
      const f = (await check(z)).findings.find((x) => x.id === "dmarc-no-rua") as Report["findings"][number];
      expect(f.fixes.map((x) => [x.action, x.value])).toEqual([["replace", "v=DMARC1; p=reject; rua=mailto:{rua}"]]);
      const [after] = await stepThrough(z, f);
      expect(ids(after as Report)).not.toContain("dmarc-no-rua");
      expect(bad(after as Report)).toEqual([]);
    },
  );

  // The chain drops a step equal to the current record however the record is written, not only as
  // dmarcValue writes it: else “v=DMARC1;p=quarantine;rua=…” would get a first step that
  // publishes the same quarantine.
  it.each([
    `v=DMARC1; p=quarantine; rua=mailto:${RUA}`,
    `v=DMARC1;p=quarantine;rua=mailto:${RUA}`,
    `v=DMARC1; p=quarantine; rua=mailto:${RUA};`,
  ])("quarantine written as %j: one fix, to reject", async (record) => {
    const z = googleZone(record);
    const f = (await check(z)).findings.find((x) => x.id === "dmarc-policy-quarantine") as Report["findings"][number];
    expect(f.fixes.map((x) => [x.action, x.value, x.step])).toEqual([
      ["replace", `v=DMARC1; p=reject; rua=mailto:${RUA}`, undefined],
    ]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });
});
