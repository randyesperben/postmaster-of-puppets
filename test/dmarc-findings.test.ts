import { describe, expect, it } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { findingText } from "../src/finding-text.ts";
import { dmarc, run } from "./helpers/dmarc.ts";
import { ids } from "./helpers/findings.ts";
import { zoneResolver } from "./helpers/zone.ts";

describe("one case per DMARC finding", () => {
  it("dmarc-enforced", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-enforced"]);
    expect(r.status).toBe("pass");
    expect(r.tags).toMatchObject({ p: "reject" });
  });

  it("dmarc-missing", async () => {
    const r = await run({});
    expect(ids(r)).toEqual(["dmarc-missing"]);
    expect(r.effective).toBeUndefined();
    expect(r.status).toBe("fail");
  });

  it("dmarc-multiple-records: both discarded", async () => {
    const r = await run({ "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject", "v=DMARC1; p=none"] } });
    expect(ids(r)).toEqual(["dmarc-multiple-records"]);
    expect(r.effective).toBeUndefined();
    expect(r.findings[0]?.severity).toBe("critical");
    expect(r.status).toBe("fail");
  });

  // RFC 7489 §6.6.3 step 5.
  it("dmarc-multiple-records on a subdomain: the parent applies for RFC 9989, no DMARC for RFC 7489", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject", "v=DMARC1; p=none"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
      "yes",
    );
    expect(ids(r)).toEqual(["dmarc-multiple-records"]);
    expect(r.foundAt).toBe("example.com");
    expect(r.effective).toBeUndefined();
    expect(r.findings[0]?.severity).toBe("critical");
    expect(r.status).toBe("fail");
    // RFC 9989 §4.10, steps 2 and 6: “If multiple DMARC Policy Records are returned for a single
    // target, they are all discarded”, and the walk goes on, so its receivers apply what
    // example.com's record sets for subdomains (§4.10.1: sp, else p); RFC 7489 §6.6.3: “If the
    // remaining set contains multiple records or no records, policy discovery terminates and DMARC
    // processing is not applied to this message”. The weaker reading decides, and the text names
    // both.
    const f = r.findings[0]!;
    expect(f.vars).toMatchObject({ weaker: 1, inherited: "example.com" });
    const why = findingText(f, "why", "shop.example.com");
    expect(why).toContain("RFC 9989");
    expect(why).toContain(
      "the policy that example.com’s DMARC record sets for subdomains (sp, or p when sp is absent)",
    );
    expect(why).toContain("RFC 7489");
    expect(why).not.toContain("left with no DMARC policy");
    expect(findingText(f, "fix", "shop.example.com")).toContain("_dmarc.shop.example.com");
  });

  it("dmarc-multiple-records with nothing above: no DMARC policy in either reading, and the text says so", async () => {
    const r = await run({ "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject", "v=DMARC1; p=none"] } });
    const f = r.findings[0]!;
    expect(f.vars?.weaker).toBeUndefined();
    expect(f.vars?.inherited).toBeUndefined();
    expect(findingText(f, "why", "example.com")).toContain("example.com is left with no DMARC policy");
  });

  it("dmarc-bad-version on a subdomain whose parent applies is a warning too", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=dmarc1; p=reject"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
      "yes",
    );
    expect(ids(r)).toEqual(["dmarc-bad-version", "dmarc-enforced"]);
    expect(r.findings[0]?.severity).toBe("warning");
    expect(r.status).toBe("weak");
  });

  it("dmarc-bad-version: v not first, or the wrong case", async () => {
    for (const rec of ["p=reject; v=DMARC1", "v=dmarc1; p=reject"]) {
      const r = await run(dmarc(rec));
      expect(ids(r), rec).toEqual(["dmarc-bad-version"]);
      expect(r.effective).toBeUndefined();
      expect(r.status).toBe("fail");
    }
  });

  it("dmarc-invalid-policy with a valid rua counts as none", async () => {
    const r = await run(dmarc("v=DMARC1; p=rejected; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-invalid-policy", "dmarc-policy-none"]);
    expect(r.effective).toBe("none");
  });

  it("dmarc-invalid-policy without rua counts as no DMARC, a missing p too", async () => {
    for (const rec of ["v=DMARC1; p=rejected", "v=DMARC1; sp=reject", "v=DMARC1; p=reject; sp=bogus"]) {
      const r = await run(dmarc(rec));
      expect(ids(r), rec).toEqual(["dmarc-invalid-policy", "dmarc-missing"]);
      expect(r.effective).toBeUndefined();
    }
  });

  it("dmarc-policy-none", async () => {
    const r = await run(dmarc("v=DMARC1; p=none; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-policy-none"]);
    expect(r.status).toBe("fail");
  });

  it("dmarc-policy-quarantine", async () => {
    const r = await run(dmarc("v=DMARC1; p=quarantine; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-policy-quarantine"]);
    expect(r.status).toBe("weak");
  });

  it("dmarc-subdomains-open with sp=none or np=none", async () => {
    const sp = await run(dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"));
    expect(ids(sp)).toEqual(["dmarc-subdomains-open"]);
    expect(sp.subdomainsOpen).toBe(true);
    const np = await run(dmarc("v=DMARC1; p=reject; np=none; rua=mailto:d@example.com"));
    expect(ids(np)).toEqual(["dmarc-subdomains-open"]);
  });

  it("sp on a record below the Organizational Domain opens nothing (§4.7)", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
    );
    expect(r.subdomainsOpen).toBe(false);
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });

  it("dmarc-no-rua", async () => {
    expect(ids(await run(dmarc("v=DMARC1; p=reject")))).toEqual(["dmarc-enforced", "dmarc-no-rua"]);
  });

  it("dmarc-rua-unauthorized: an outside address with no _report._dmarc record", async () => {
    const r = await run(dmarc("v=DMARC1; p=none; rua=mailto:reports@dmarc-vendor.example"));
    expect(ids(r)).toEqual(["dmarc-policy-none", "dmarc-rua-unauthorized"]);
    expect(r.findings[1]?.vars?.host).toBe("dmarc-vendor.example");
  });

  it("an outside address authorized by name or by a wildcard", async () => {
    const byName = await run(
      dmarc("v=DMARC1; p=reject; rua=mailto:r@dmarc-vendor.example", {
        "example.com._report._dmarc.dmarc-vendor.example": { TXT: ["v=DMARC1"] },
      }),
    );
    expect(ids(byName)).toEqual(["dmarc-enforced"]);
    const resolver = zoneResolver(
      dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.example.net", {
        "*._report._dmarc.vendor.example.net": { TXT: ["v=DMARC1;"] },
      }),
    );
    expect(ids(await checkDmarc({ resolver }, "example.com"))).toEqual(["dmarc-enforced"]);
    expect(resolver.asked).toContain("example.com._report._dmarc.vendor.example.net TXT");
  });

  it("an address on the domain's own subdomain needs no authorization and no lookup", async () => {
    const resolver = zoneResolver(dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.com"));
    expect(ids(await checkDmarc({ resolver }, "example.com"))).toEqual(["dmarc-enforced"]);
    expect(resolver.asked.some((q) => q.includes("_report"))).toBe(false);
  });

  it("an address in another domain with the same Organizational Domain is authorized", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      },
      "shop.example.com",
    );
    expect(r.orgDomain).toBe("example.com");
    expect(ids(r)).toEqual(["dmarc-enforced"]);
    const sibling = await run({
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@other.example.org"] },
      "_dmarc.example.org": { TXT: ["v=DMARC1; p=none"] },
      "_dmarc.other.example.org": { TXT: ["v=DMARC1; p=none"] },
    });
    expect(ids(sibling)).toEqual(["dmarc-enforced", "dmarc-rua-unauthorized"]);
  });

  it("a rua that cannot be checked is not called unauthorized", async () => {
    const r = await run(
      dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.example.net", {
        "_dmarc.vendor.example.net": { $unreachable: true },
      }),
    );
    expect(ids(r)).toEqual(["dmarc-enforced"]);
    const late = await run(
      dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.example.net", {
        "example.com._report._dmarc.vendor.example.net": { $unreachable: true },
      }),
    );
    expect(ids(late)).toEqual(["dmarc-enforced"]);
  });

  it("a destination name over 253 octets cannot be authorized", async () => {
    const host = `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(40)}.example.net`;
    expect(`example.com._report._dmarc.${host}`.length).toBeGreaterThan(253);
    const r = await run(dmarc(`v=DMARC1; p=reject; rua=mailto:r@${host}`));
    expect(ids(r)).toContain("dmarc-rua-unauthorized");
  });

  // RFC 9991 §5: “a Mail Receiver who generates failure reports MUST use the Verifying External
  // Destinations procedure described in Section 4 of [RFC9990], substituting the "ruf" tag where
  // the "rua" tag appears in that procedure” (rfc-editor.org, read 2026-11-20).
  it("a ruf outside the domain needs the same authorization as a rua", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; ruf=mailto:f@dmarc-vendor.example"));
    expect(ids(r)).toEqual(["dmarc-enforced", "dmarc-no-rua", "dmarc-ruf", "dmarc-rua-unauthorized"]);
    expect(r.findings[3]).toMatchObject({
      found: "mailto:f@dmarc-vendor.example",
      vars: { host: "dmarc-vendor.example" },
    });
    const both = await run(
      dmarc("v=DMARC1; p=reject; rua=mailto:r@dmarc-vendor.example; ruf=mailto:f@dmarc-vendor.example"),
    );
    expect(ids(both).filter((id) => id === "dmarc-rua-unauthorized")).toHaveLength(1);
    const authorized = await run(
      dmarc("v=DMARC1; p=reject; ruf=mailto:f@dmarc-vendor.example", {
        "example.com._report._dmarc.dmarc-vendor.example": { TXT: ["v=DMARC1"] },
      }),
    );
    expect(ids(authorized)).toEqual(["dmarc-enforced", "dmarc-no-rua", "dmarc-ruf"]);
  });

  it("dmarc-ruf", async () => {
    expect(ids(await run(dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com; ruf=mailto:f@example.com")))).toEqual([
      "dmarc-enforced",
      "dmarc-ruf",
    ]);
  });

  it("dmarc-tag-typo", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; rua:mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-tag-typo", "dmarc-enforced", "dmarc-no-rua"]);
    expect(r.findings[0]?.found).toBe("rua:mailto:d@example.com");
  });

  it("record-name-doubled at _dmarc.<domain>.<domain> and at <domain>.<domain>", async () => {
    const r = await run({
      "_dmarc.example.com.example.com": { TXT: ["v=DMARC1; p=reject"] },
      "example.com.example.com": { TXT: ["v=spf1 include:_spf.example.net -all"] },
    });
    const doubled = r.findings.filter((f) => f.id === "record-name-doubled");
    expect(doubled.map((f) => f.group)).toEqual(["dmarc"]);
    expect(r.spfDoubled.map((f) => [f.id, f.group])).toEqual([["record-name-doubled", "spf"]]);
    expect(ids(r)).toContain("dmarc-missing");
  });

  it("an SPF record at <domain>.<domain> stays out of the DMARC findings and status", async () => {
    const r = await run({
      "example.com.example.com": { TXT: ["v=spf1 include:_spf.example.net -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
    });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
    expect(r.status).toBe("pass");
    expect(r.spfDoubled).toHaveLength(1);
    expect(r.spfDoubled[0]?.found).toBe("example.com.example.com v=spf1 include:_spf.example.net -all");
  });

  it("record-name-doubled stays quiet when a wildcard answers every name", async () => {
    const r = await run({
      "*.example.com": { TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
    });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });
});
