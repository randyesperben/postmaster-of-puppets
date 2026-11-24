// The two DMARC readings, RFC 9989's Tree Walk and RFC 7489's Public Suffix List, through full
// checks: sp read as p is, the Organizational Domain by the PSL, when the weaker reading decides
// (weaker), and a parent's record discarded on the way.
import { describe, expect, it } from "vitest";
import type { Finding } from "../src/types.ts";
import {
  bad,
  brokenParent,
  check,
  googleZone,
  inheritingShop,
  P4,
  RUA,
  SOA,
  stepThrough,
  weakerOf,
} from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

describe("the two readings apply to sp as they do to p", () => {
  // RFC 7489 reads SP=none as sp=none.
  it("p=reject; SP=none: subdomains are open for RFC 7489 receivers; the typo carries `weaker`", async () => {
    const z = googleZone(`v=DMARC1; p=reject; SP=none; rua=mailto:${RUA}`);
    const r = await check(z);
    expect(r.verdict).toBe("partly-protected");
    expect(weakerOf(r)).toEqual(["dmarc-tag-typo"]);
    const open = r.findings.find((f) => f.id === "dmarc-subdomains-open");
    expect(open?.vars).toMatchObject({ sp: "none", np: "none" });
    // Its steps rewrite the record without the mistyped tag: both readings end at reject.
    const steps = await stepThrough(z, open as Finding);
    expect(steps.at(-1)?.verdict).toBe("protected");
    for (const s of steps) expect(bad(s).filter((id) => id !== "dmarc-subdomains-open")).toEqual([]);
  });

  it("sp=reject; SP=none: RFC 7489 keeps the weaker copy (§6.3), RFC 9989 reads sp=reject", async () => {
    const r = await check(googleZone(`v=DMARC1; p=reject; sp=reject; SP=none; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("partly-protected");
    expect(weakerOf(r)).toEqual(["dmarc-tag-typo"]);
  });

  it("both readings agree: no `weaker`", async () => {
    const open = await check(googleZone(`v=DMARC1; p=reject; sp=none; rua=mailto:${RUA}`));
    expect(open.verdict).toBe("partly-protected");
    expect(weakerOf(open)).toEqual([]);
    const closed = await check(googleZone(`v=DMARC1; p=reject; SP=reject; rua=mailto:${RUA}`));
    expect(closed.verdict).toBe("protected");
    expect(weakerOf(closed)).toEqual([]);
  });

  it("no `weaker` when the stronger reading gives the same verdict: SP=none with an open SPF", async () => {
    const z = googleZone(`v=DMARC1; p=reject; SP=none; rua=mailto:${RUA}`);
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com +all"];
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(weakerOf(r)).toEqual([]);
  });
});

describe("a subdomain under a public suffix of several labels reaches its Organizational Domain by the PSL", () => {
  for (const suffix of ["co.uk", "com.au", "com.br", "co.jp", "com.mx", "co.nz", "github.io"]) {
    it(`shop.example.${suffix} without a record of its own, example.${suffix} at reject: Protected`, async () => {
      const org = `example.${suffix}`;
      const zone: Zone = {
        [org]: { SOA },
        [`shop.${org}`]: { A: [P4] },
        [`_dmarc.${org}`]: { TXT: [`v=DMARC1; p=reject; rua=mailto:dmarc@${org}`] },
      };
      const r = await check(zone, `shop.${org}`);
      expect(r.verdict).toBe("protected");
      expect(r.dmarc.orgDomain).toBe(org);
      expect(ids(r)).not.toContain("dmarc-org-differs");
    });
  }
});

describe("weaker: when the weaker reading decides", () => {
  it("pct=50 lowers only the RFC 7489 reading (RFC 9989 Appendix A.6): dmarc-pct carries `weaker`", async () => {
    const r = await check(googleZone(`v=DMARC1; p=reject; pct=50; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("partly-protected");
    expect(weakerOf(r)).toEqual(["dmarc-pct"]);
  });

  it("V=DMARC1 alone at the apex: RFC 7489 reads reject, so dmarc-bad-version carries `weaker`", async () => {
    const r = await check(googleZone(`V=DMARC1; p=reject; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("spoofable");
    expect(weakerOf(r)).toEqual(["dmarc-bad-version"]);
  });

  it("P=reject: RFC 7489 reads reject, RFC 9989 no policy; the typo carries `weaker`", async () => {
    const r = await check(googleZone(`v=DMARC1; P=reject; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("spoofable");
    expect(weakerOf(r)).toEqual(["dmarc-tag-typo"]);
  });

  // shop is shop.example.com; RFC 7489 leaves its subdomains open.
  it("shop at p=reject, no record at example.com: dmarc-subdomains-open carries `weaker`", async () => {
    const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
    z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] };
    delete z["_dmarc.example.com"];
    const r = await check(z, "shop.example.com");
    expect(r.verdict).toBe("partly-protected");
    expect(weakerOf(r)).toEqual(["dmarc-subdomains-open"]);
    expect(r.findings.find((f) => f.id === "dmarc-subdomains-open")?.vars).toMatchObject({
      pslOrgDomain: "example.com",
      pslMissing: 1,
    });
  });

  it("no `weaker` when the stronger reading gives the same verdict: t=y with an open SPF or sp=none", async () => {
    const open = googleZone(`v=DMARC1; p=reject; t=y; rua=mailto:${RUA}`);
    (open["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com +all"];
    const a = await check(open);
    expect(a.verdict).toBe("spoofable");
    expect(weakerOf(a)).toEqual([]);
    const b = await check(googleZone(`v=DMARC1; p=reject; sp=none; t=y; rua=mailto:${RUA}`));
    expect(b.verdict).toBe("partly-protected");
    expect(weakerOf(b)).toEqual([]);
  });

  it("pct=0 lowers the policy one level in both readings: no `weaker`", async () => {
    const r = await check(googleZone(`v=DMARC1; p=reject; pct=0; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("partly-protected");
    expect(ids(r)).toContain("dmarc-pct");
    expect(weakerOf(r)).toEqual([]);
  });
});

// The parent's record is discarded on the way; the checked name gets dmarc-missing and its fix,
// and a warning names the parent's broken record.
describe("a parent's record discarded on the way", () => {
  // prettier-ignore
  for (const [what, records, id, vars] of [
    ["two records", [`v=DMARC1; p=reject; rua=mailto:${RUA}`, "v=DMARC1; p=none"],
      "dmarc-multiple-records", { at: "example.com" }],
    ["a tag repeated with two values", [`v=DMARC1; p=reject; p=none; rua=mailto:${RUA}`],
      "dmarc-bad-version", { at: "example.com", reason: "repeated-tag", tag: "p" }],
    ["v=DMARC2", ["v=DMARC2; p=reject"],
      "dmarc-bad-version", { at: "example.com" }],
  ] as const) {
    it(`${what} at example.com: shop.example.com has dmarc-missing and a warning with at`, async () => {
      const r = await brokenParent([...records]);
      expect(r.findings.find((f) => f.id === "dmarc-missing")?.severity).toBe("critical");
      expect(r.findings.find((f) => f.id === id)).toMatchObject({ severity: "warning", vars });
      expect(r.verdict).toBe("spoofable");
    });
  }

  // RFC 7489 reads tag names without case and a repeated tag with its weaker value (§6.3, §6.4),
  // so these parents give its receivers reject while RFC 9989 discards them: two levels, so the
  // cause is critical and carries weaker.
  // prettier-ignore
  for (const [what, record, vars] of [
    ["V=DMARC1", `V=DMARC1; p=reject; rua=mailto:${RUA}`,
      { at: "example.com", weaker: 1 }],
    ["rua twice", `v=DMARC1; p=reject; rua=mailto:${RUA}; rua=mailto:${RUA}`,
      { at: "example.com", reason: "repeated-tag", tag: "rua", weaker: 1 }],
    ["p=reject twice", `v=DMARC1; p=reject; p=reject; rua=mailto:${RUA}`,
      { at: "example.com", reason: "repeated-tag", tag: "p", weaker: 1 }],
  ] as const) {
    // RFC 7489 receivers apply reject to shop.example.com.
    it(`${what} at example.com: the cause is critical with \`weaker\``, async () => {
      const r = await brokenParent([record]);
      expect(r.findings.find((f) => f.id === "dmarc-bad-version")).toMatchObject({ severity: "critical", vars });
      expect(r.findings.find((f) => f.id === "dmarc-missing")?.severity).toBe("critical");
      expect(r.verdict).toBe("spoofable");
    });
  }
});
