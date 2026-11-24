import { describe, expect, it } from "vitest";
import { dmarc, run } from "./helpers/dmarc.ts";
import { ids } from "./helpers/findings.ts";
import type { Zone } from "./helpers/zone.ts";

describe("effective policy", () => {
  const org = (record: string) => ({ "_dmarc.example.com": { TXT: [record] } });

  it("the name's own record: p", async () => {
    expect((await run(dmarc("v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@example.com"))).effective).toBe(
      "quarantine",
    );
  });

  // When existence is unknown and np asks for less than sp, DMARC stays unanswered.
  it("inherited: sp for a name that exists, np for one that does not", async () => {
    const z = org("v=DMARC1; p=reject; sp=quarantine; np=none; rua=mailto:d@example.com");
    expect(await run(z, "shop.example.com", "yes")).toMatchObject({ effective: "quarantine", policyFrom: "sp" });
    expect(await run(z, "shop.example.com", "nxdomain")).toMatchObject({ effective: "none", policyFrom: "np" });
    expect(await run(z, "shop.example.com", "nxname")).toMatchObject({ effective: "none", policyFrom: "np" });
    const unknown = await run(z, "shop.example.com");
    expect(unknown).toMatchObject({ failed: true, status: "unknown" });
    expect(unknown.effective).toBeUndefined();
    expect(ids(unknown)).toContain("lookup-failed");
    // np asking for more than sp: sp applies whether the name exists or not.
    expect(
      await run(org("v=DMARC1; p=reject; sp=quarantine; np=reject; rua=mailto:d@example.com"), "shop.example.com"),
    ).toMatchObject({ effective: "quarantine", failed: false });
  });

  it("np falls back to sp, then p (§4.7)", async () => {
    expect(
      await run(org("v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"), "x.example.com", "nxdomain"),
    ).toMatchObject({ effective: "quarantine", policyFrom: "sp" });
    expect(await run(org("v=DMARC1; p=reject; rua=mailto:d@example.com"), "x.example.com", "nxdomain")).toMatchObject({
      effective: "reject",
      policyFrom: "p",
    });
    expect(await run(org("v=DMARC1; p=reject; rua=mailto:d@example.com"), "x.example.com")).toMatchObject({
      effective: "reject",
      policyFrom: "p",
    });
    expect(
      await run(org("v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"), "x.example.com"),
    ).toMatchObject({ effective: "quarantine", policyFrom: "sp" });
  });

  it("t=y lowers one level", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; t=y; rua=mailto:d@example.com"));
    expect(r.effective).toBe("quarantine");
    expect(ids(r)).toEqual(["dmarc-testing-mode", "dmarc-policy-quarantine"]);
  });

  it("quarantine with pct=0 and pct=25 counts as none; reject with pct=0 as quarantine", async () => {
    const q0 = await run(dmarc("v=DMARC1; p=quarantine; pct=0; rua=mailto:d@example.com"));
    expect(q0.effective).toBe("none");
    expect(ids(q0)).toEqual(["dmarc-pct", "dmarc-policy-none"]);
    expect((await run(dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com"))).effective).toBe("none");
    expect((await run(dmarc("v=DMARC1; p=reject; pct=0; rua=mailto:d@example.com"))).effective).toBe("quarantine");
    expect((await run(dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:d@example.com"))).effective).toBe("reject");
    expect((await run(dmarc("v=DMARC1; p=reject; pct=abc; rua=mailto:d@example.com"))).effective).toBe("reject");
  });

  it("t=y and pct together still lower one level only", async () => {
    expect((await run(dmarc("v=DMARC1; p=reject; t=y; pct=50; rua=mailto:d@example.com"))).effective).toBe(
      "quarantine",
    );
  });

  it("t=y on p=none changes nothing and raises no testing finding", async () => {
    expect(ids(await run(dmarc("v=DMARC1; p=none; t=y; rua=mailto:d@example.com")))).toEqual(["dmarc-policy-none"]);
  });

  it("t=y lowers sp and np too: sp=quarantine leaves subdomains at none", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; sp=quarantine; t=y; rua=mailto:d@example.com"));
    expect(r.subdomainsOpen).toBe(true);
    expect(ids(r)).toEqual(["dmarc-testing-mode", "dmarc-policy-quarantine", "dmarc-subdomains-open"]);
    expect(r.findings[2]?.vars).toMatchObject({ sp: "none", np: "none", at: "example.com" });
  });

  it("an invalid sp or np with a valid rua counts as p=none (§4.10.1)", async () => {
    for (const rec of [
      "v=DMARC1; p=reject; sp=bogus; rua=mailto:d@example.com",
      "v=DMARC1; p=reject; np=strict; rua=mailto:d@example.com",
    ]) {
      const r = await run(dmarc(rec));
      expect(ids(r), rec).toEqual(["dmarc-invalid-policy", "dmarc-policy-none"]);
      expect(r.effective, rec).toBe("none");
    }
  });

  it("an upper-case P is not a policy: only P= means no valid p", async () => {
    const r = await run(dmarc("v=DMARC1; P=reject; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-tag-typo", "dmarc-invalid-policy", "dmarc-policy-none"]);
    expect(r.effective).toBe("none");
    expect(ids(await run(dmarc("v=DMARC1; P=reject")))).toEqual([
      "dmarc-tag-typo",
      "dmarc-invalid-policy",
      "dmarc-missing",
    ]);
  });

  it("a TXT record split into several strings is read joined", async () => {
    const r = await run({ "_dmarc.example.com": { TXT: [["v=DMARC1; p=re", "ject; rua=mailto:d@example.com"]] } });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });
});

describe("subdomains of a name with its own record", () => {
  it("are judged by the Organizational Domain's sp and np, not by the name's own record", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=none; np=none; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
    );
    expect(r).toMatchObject({
      foundAt: "shop.example.com",
      orgDomain: "example.com",
      policyFrom: "p",
      effective: "reject",
      subdomainsOpen: true,
      status: "weak",
    });
    expect(ids(r)).toEqual(["dmarc-subdomains-open"]);
    expect(r.findings[0]?.vars).toMatchObject({ sp: "none", np: "none", at: "example.com" });
  });

  it("with t=y on the Organizational Domain, its sp=quarantine leaves them at none", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=quarantine; t=y; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
    );
    expect(r.subdomainsOpen).toBe(true);
  });

  it("with an invalid Organizational Domain record and no rua, subdomains have no DMARC at all", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=rejected"] },
      },
      "shop.example.com",
    );
    expect(r.subdomainsOpen).toBe(true);
    expect(ids(r)).toEqual(["dmarc-subdomains-open"]);
  });

  it("under a PSD, by the PSD's sp when the Organizational Domain has no record", async () => {
    const r = await run(
      {
        "_dmarc.mail.mega.bank.example": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@mega.bank.example"] },
        "_dmarc.bank.example": { TXT: ["v=DMARC1; p=reject; sp=none; psd=y"] },
      },
      "mail.mega.bank.example",
    );
    expect(r).toMatchObject({
      foundAt: "mail.mega.bank.example",
      orgDomain: "mega.bank.example",
      subdomainsOpen: true,
    });
    expect(r.findings.find((f) => f.id === "dmarc-subdomains-open")?.vars).toMatchObject({ at: "bank.example" });
  });

  it("psd=n on the name's own record makes it the Organizational Domain: its own sp applies", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; psd=n; rua=mailto:d@shop.example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
    );
    expect(r).toMatchObject({ orgDomain: "shop.example.com", strongerOpen: false });
    // RFC 7489 knows no psd: its receivers read x.shop.example.com at example.com, whose sp=none
    // leaves them open, and the weaker reading counts.
    expect(r.subdomainsOpen).toBe(true);
    expect(ids(r)).toEqual(["dmarc-subdomains-open"]);
  });
});

describe("an incomplete walk above a name with its own record", () => {
  const shop = (record: string): Zone => ({
    "_dmarc.shop.example.com": { TXT: [record] },
    "_dmarc.example.com": { $unreachable: true },
  });

  it("cannot say whether subdomains are protected: failed, no Organizational Domain, no dmarc-enforced", async () => {
    const r = await run(shop("v=DMARC1; p=reject; rua=mailto:d@example.com"), "shop.example.com");
    expect(r).toMatchObject({
      failed: true,
      foundAt: "shop.example.com",
      effective: "reject",
      subdomainsOpen: false,
      status: "unknown",
    });
    expect(r.orgDomain).toBeUndefined();
    expect(ids(r)).toEqual(["lookup-failed"]);
    expect(r.findings[0]).toMatchObject({ group: "dmarc", found: "_dmarc.example.com TXT" });
  });

  it("does not trust the name's own sp=none either (§4.7: sp is ignored below the Organizational Domain)", async () => {
    const r = await run(shop("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"), "shop.example.com");
    expect(ids(r)).toEqual(["lookup-failed"]);
  });

  // RFC 7489 receivers read the subdomains at example.com.
  it("psd=n on the name's own record: RFC 9989 is answered and RFC 7489 is not", async () => {
    const r = await run(shop("v=DMARC1; p=reject; psd=n; rua=mailto:d@shop.example.com"), "shop.example.com");
    expect(r).toMatchObject({ failed: true, orgDomain: "shop.example.com", status: "unknown" });
    expect(r.findings.find((f) => f.id === "lookup-failed")?.found).toBe("_dmarc.example.com TXT");
    expect(ids(r)).not.toContain("dmarc-enforced");
  });

  // A record at the TLD without psd=y would be the Organizational Domain.
  it("a failure at the TLD alone is enough to leave the walk unanswered", async () => {
    const r = await run({
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      "_dmarc.com": { $unreachable: true },
    });
    expect(r.failed).toBe(true);
    expect(r.orgDomain).toBeUndefined();
    expect(ids(r)).toEqual(["lookup-failed"]);
    expect(r.findings[0]?.found).toBe("_dmarc.com TXT");
  });

  // Whether a parent's record applies is unknown.
  it("the name's own record discarded with the walk incomplete is a warning", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject", "v=DMARC1; p=none"] },
        "_dmarc.example.com": { $unreachable: true },
      },
      "shop.example.com",
    );
    expect(r.failed).toBe(true);
    expect(ids(r)).toEqual(["dmarc-multiple-records", "lookup-failed"]);
    expect(r.findings[0]?.severity).toBe("warning");
    expect(r.status).toBe("unknown");
  });
});

describe("failures", () => {
  it("lookup-failed on the name's own record: the verdict cannot be given", async () => {
    const r = await run({ "_dmarc.example.com": { $unreachable: true } });
    expect(ids(r)).toEqual(["lookup-failed"]);
    expect(r.findings[0]?.group).toBe("dmarc");
    expect(r.failed).toBe(true);
    expect(r.status).toBe("unknown");
  });

  it("lookup-failed on a parent when the name has no record", async () => {
    const r = await run({ "_dmarc.example.com": { $unreachable: true } }, "shop.example.com");
    expect(r.failed).toBe(true);
  });

  it("a failed lookup before the psd stop counts; one after it is never read", async () => {
    const before = await run(
      {
        "_dmarc.mail.example.com": { $unreachable: true },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com"] },
      },
      "a.mail.example.com",
    );
    expect(before.failed).toBe(true);
    expect(before.findings.find((f) => f.id === "lookup-failed")?.found).toBe("_dmarc.mail.example.com TXT");
    const after = await run(
      {
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com"] },
        "_dmarc.com": { $unreachable: true },
      },
      "a.mail.example.com",
      "yes",
    );
    expect(after).toMatchObject({ failed: false, orgDomain: "example.com", effective: "reject" });
  });

  it("dnssec-broken on _dmarc: reported, with the published record read through CD", async () => {
    const r = await run({
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"], $servfail: true },
    });
    expect(ids(r)).toEqual(["dnssec-broken", "dmarc-enforced"]);
    expect(r.dnssecBroken).toBe(true);
    // The verdict is Can't tell, so the group is unknown, not fail.
    expect(r.status).toBe("unknown");
  });

  it("dnssec-broken on the Organizational Domain above a name with its own record", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=none"], $servfail: true },
      },
      "shop.example.com",
    );
    expect(r.dnssecBroken).toBe(true);
    expect(r.findings[0]).toMatchObject({ id: "dnssec-broken", found: "_dmarc.example.com TXT" });
    expect(r.status).toBe("unknown");
  });
});
