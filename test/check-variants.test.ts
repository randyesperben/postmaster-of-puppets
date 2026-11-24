// The variants of the catalog's entries (CatalogEntry in types.ts), through full checks: a case
// where the engine emits each one, and the texts each one changes.
import { describe, expect, it } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { catalog } from "../src/index.ts";
import type { Finding } from "../src/types.ts";
import { brokenParent, check, DKIM, googleZone, inheritingShop, RUA, signedNoKeys } from "./helpers/check.ts";
import { type Node, zoneResolver } from "./helpers/zone.ts";

describe("catalog variants", () => {
  const orgOpen = (spf: string) => {
    const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
    (z["example.com"] as Node).TXT = [spf];
    (z["shop.example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com -all"];
    return check(z, "shop.example.com");
  };
  /** One real case per variant, “<id>:<when>”: the engine must emit that var on that id. */
  const CASES: Record<string, () => Promise<{ findings: Finding[] }>> = {
    // checkDomain always loads the real chunk, so the DMARC check alone stands in.
    "lookup-failed:list": () =>
      checkDmarc(
        { resolver: zoneResolver({ "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] } }) },
        "news.mail.example.com",
        {
          exists: "yes",
          psl: () => Promise.reject(new Error("chunk")),
        },
      ),
    "spf-plus-all:org": () => orgOpen("v=spf1 +all"),
    "spf-open-range:org": () => orgOpen("v=spf1 ip4:0.0.0.0/0 -all"),
    "mx-null:sending": () => {
      const z = googleZone();
      (z["example.com"] as Node).MX = ["0 ."];
      return check(z);
    },
    "mx-null:sendingUnknown": () => {
      const z = googleZone();
      (z["example.com"] as Node).MX = ["0 ."];
      (z["example.com"] as Node).TXT = ["v=spf1 -all"];
      z["google._domainkey.example.com"] = { $unreachable: true };
      return check(z);
    },
    "dmarc-multiple-records:at": () => brokenParent([`v=DMARC1; p=reject; rua=mailto:${RUA}`, "v=DMARC1; p=none"]),
    "dmarc-bad-version:at": () => brokenParent(["v=DMARC2; p=reject"]),
    // Two records at shop.example.com under example.com's p=reject.
    "dmarc-multiple-records:inherited": () => {
      const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`, "v=DMARC1; p=none"] };
      return check(z, "shop.example.com");
    },
    "dmarc-multiple-records:weaker": () => {
      const z = googleZone(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
      (z["_dmarc.example.com"] as Node).TXT = [`v=DMARC1; p=reject; rua=mailto:${RUA}`, "V=DMARC1; p=none"];
      return check(z);
    },
    "dmarc-bad-version:weaker": () => check(googleZone(`V=DMARC1; p=reject; rua=mailto:${RUA}`)),
    // RFC 9989 opens them too, and two records at the RFC 7489 Organizational Domain.
    "dmarc-subdomains-open:both": () => {
      const z = inheritingShop("");
      delete z["_dmarc.example.com"];
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; sp=none; rua=mailto:${RUA}`] };
      return check(z, "shop.example.com");
    },
    "dmarc-subdomains-open:pslSeveral": () => {
      const z = inheritingShop("v=DMARC1; p=reject");
      (z["_dmarc.example.com"] as Node).TXT = ["v=DMARC1; p=reject", "V=DMARC1; p=reject"];
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; psd=n; rua=mailto:${RUA}`] };
      return check(z, "shop.example.com");
    },
    "dmarc-subdomains-open:pslMissing": () => {
      const z = inheritingShop("");
      delete z["_dmarc.example.com"];
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] };
      return check(z, "shop.example.com");
    },
    // Signed DNS denies _domainkey.
    "dkim-not-found:none": () => signedNoKeys(),
    // A wildcard under _domainkey answers every selector, so none is credited.
    "dkim-not-found:wildcard": () => {
      const z = googleZone();
      delete z["google._domainkey.example.com"];
      z["*._domainkey.example.com"] = { TXT: [DKIM] };
      return check(z);
    },
    // A key off the list.
    "dkim-not-found:hidden": () => {
      const z = googleZone();
      delete z["google._domainkey.example.com"];
      z["x9._domainkey.example.com"] = { TXT: [DKIM] };
      return check(z);
    },
    // A typed selector.
    "dkim-not-found:typed": () => {
      const z = googleZone();
      delete z["google._domainkey.example.com"];
      return check(z, "example.com", { extraSelectors: ["custom2026"] });
    },
    // A short SPF among old verification records.
    "spf-too-large:others": () => {
      const z = googleZone();
      (z["example.com"] as Node).TXT = [
        ...((z["example.com"] as Node).TXT as string[]),
        ...Array.from({ length: 6 }, (_, i) => `site-verification-${i}=${"v".repeat(60)}`),
      ];
      return check(z);
    },
    // RFC 8461 §3.3: the policy host has an IPv6 address only.
    "mta-sts-policy-unreachable:ipv6Only": () => {
      const z = googleZone();
      z["_mta-sts.example.com"] = { TXT: ["v=STSv1; id=2026111801"] };
      z["mta-sts.example.com"] = { AAAA: ["2001:db8::10"] };
      return check(z);
    },
    "dmarc-subdomains-open:pslOrgDomain": () => {
      const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
      z["_dmarc.shop.example.com"] = { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] };
      delete z["_dmarc.example.com"];
      return check(z, "shop.example.com");
    },
  };

  it("every variant has a case where the engine emits its var on that id", async () => {
    const keys = catalog.flatMap((e) => (e.variants ?? []).map((v) => `${e.id}:${v.when}`));
    expect(keys.sort()).toEqual(Object.keys(CASES).sort());
    for (const [key, run] of Object.entries(CASES)) {
      const [id, when] = key.split(":") as [string, keyof NonNullable<Finding["vars"]>];
      const r = await run();
      expect(
        r.findings.some((f) => f.id === id && f.vars?.[when] !== undefined),
        key,
      ).toBe(true);
    }
  });

  it("every variant changes some text, and only texts it changes", () => {
    for (const e of catalog) {
      for (const v of e.variants ?? []) {
        const fields = (["title", "why", "fix"] as const).filter((k) => v[k] !== undefined);
        expect(fields.length, `${e.id}:${v.when}`).toBeGreaterThan(0);
        for (const k of fields) expect(v[k], `${e.id}:${v.when} ${k}`).not.toBe(e[k]);
      }
    }
  });
});
