// DKIM through full checks: a domain whose signed DNS denies _domainkey, the recorded checks of
// domains on Microsoft 365, which keeps one of its two selectors dangling, and delivery with keys
// that are broken or in testing mode.
import { describe, expect, it } from "vitest";
import { checkDomain } from "../src/index.ts";
import type { Finding } from "../src/types.ts";
import { check, googleZone, input, P4, signedNoKeys, SOA } from "./helpers/check.ts";
import { rsaKey } from "./helpers/keys.ts";
import { fixtureResolver } from "./helpers/dns.ts";
import { ids } from "./helpers/findings.ts";
import type { Zone } from "./helpers/zone.ts";

describe("a domain whose signed DNS denies _domainkey", () => {
  it("with mail: a warning, the DKIM group weak, delivery unknown with dkim-not-found as its cause", async () => {
    const r = await signedNoKeys();
    const f = r.findings.find((x) => x.id === "dkim-not-found");
    expect(f).toMatchObject({ severity: "warning", vars: { none: 1 } });
    expect(r.groups.dkim).toBe("weak");
    expect(r.mailUse).toBe("mail");
    expect(r.delivery).toBe("unknown");
    expect(r.deliveryCause).toEqual({ rule: 6, finding: "dkim-not-found" });
    expect(r.verdict).toBe("protected");
  });

  // The fix is the *._domainkey record.
  it("a null MX with no signs of sending: dkim-not-found without a variant, the DKIM group unknown", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    };
    const r = await signedNoKeys(z);
    expect(r.mailUse).toBe("none-declared");
    const f = r.findings.find((x) => x.id === "dkim-not-found") as Finding;
    expect(f.severity).toBe("info");
    expect(f.vars?.none).toBeUndefined();
    expect(r.groups.dkim).toBe("unknown");
    expect(f.fixes.map((x) => x.name)).toEqual(["*._domainkey.example.com"]);
  });

  it("the info goes back below a DMARC warning (check.ts sorts again)", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; pct=50;"] },
    };
    const r = await signedNoKeys(z);
    expect(r.mailUse).toBe("none-declared");
    expect(r.findings.filter((x) => x.severity === "warning").map((x) => x.group)).toContain("dmarc");
    const ORDER = { critical: 0, warning: 1, info: 2, pass: 3 };
    const order = r.findings.map((x) => ORDER[x.severity]);
    expect(order).toEqual([...order].sort((a, b) => a - b));
  });

  it("no MX, no SPF and no key (probably no mail): back to info too", async () => {
    const z: Zone = { "example.com": { SOA, A: [P4] }, "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] } };
    const r = await signedNoKeys(z);
    expect(r.mailUse).toBe("probably-none");
    expect(r.findings.find((x) => x.id === "dkim-not-found")).toMatchObject({
      severity: "info",
      vars: { tried: expect.any(Number) },
    });
    expect(r.findings.find((x) => x.id === "dkim-not-found")?.vars?.none).toBeUndefined();
    expect(r.groups.dkim).toBe("unknown");
  });
});

describe("recorded full checks (2026-11-18)", () => {
  // The fixture recorder (in the source of postmasterofpuppets.com) saved only the names on its
  // list: the others' lookups fail, so these tests look only at what the recorded names decide.
  for (const domain of ["microsoft.com", "github.com"]) {
    it(`${domain}: Microsoft 365 with one selector dangling is not flagged`, async () => {
      const r = await checkDomain(input(domain), { resolver: fixtureResolver() });
      expect(r.providers).toContain("microsoft-365");
      expect(r.dkim.keys.some((k) => k.selector === "selector1" || k.selector === "selector2")).toBe(true);
      expect(ids(r)).not.toContain("dkim-dangling-cname");
      expect(r.groups.dkim).not.toBe("fail");
    });
  }
});

describe("delivery with broken or testing keys", () => {
  it("a wildcard of broken keys does not put delivery at risk", async () => {
    const r = await check({ ["*._domainkey.example.com"]: { TXT: ["v=DKIM1; p=AAAA"] } });
    expect(r.findings.filter((f) => f.group === "dkim").map((f) => f.id)).toEqual(["dkim-not-found"]);
    expect(r.delivery).not.toBe("at-risk");
  });

  it("with every key in testing mode, delivery is not ok", async () => {
    const zone = (dkim: string): Zone => ({ ...googleZone(), "google._domainkey.example.com": { TXT: [dkim] } });
    const b = rsaKey(2048);
    expect((await check(zone(`v=DKIM1; p=${b}`))).delivery).toBe("ok");
    const testing = await check(zone(`v=DKIM1; t=y; p=${b}`));
    expect(testing.findings.map((f) => f.id)).toContain("dkim-testing-mode");
    expect(testing.delivery).not.toBe("ok");
  });
});
