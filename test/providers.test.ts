// providers.ts: the provider table, the selectors the check tries, and how an MX host, an include
// or a DKIM key's CNAME target names its provider.
import { describe, expect, it } from "vitest";
import { selectorSources } from "../data/sources/index.ts";
import {
  ownerOf,
  providerList,
  providersForInclude,
  providersForMx,
  rotationGroupOf,
  SELECTORS,
  sendingServices,
} from "../src/providers.ts";

describe("providers", () => {
  // Every provider's selectors are among them.
  it("SELECTORS: plain lower-case selectors, each once, Google's and Microsoft's first", () => {
    expect(new Set(SELECTORS).size).toBe(SELECTORS.length);
    for (const s of SELECTORS) expect(s).toMatch(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/);
    for (const p of providerList) for (const s of p.dkimSelectors) expect(SELECTORS, `${p.id}: ${s}`).toContain(s);
    expect(SELECTORS.slice(0, 3)).toEqual(["google", "selector1", "selector2"]);
  });

  // Mailchimp's page names k2 only, so k1 is seen, not documented.
  it("every selector has a vendor page, except k1, k3 and mandrill, which say where they were seen", () => {
    expect(selectorSources.map((s) => s.selector)).toEqual([...SELECTORS]);
    for (const s of selectorSources) {
      expect(s.basis, s.selector).toBe(["k1", "k3", "mandrill"].includes(s.selector) ? "dns" : "vendor");
      if (s.basis === "vendor") expect(s.url?.startsWith("https://"), s.selector).toBe(true);
      else expect(s.seenOn?.length, s.selector).toBeGreaterThan(0);
    }
  });

  // Each value's source, the selectors' among them, is checked in sources.test.ts.
  it("a rotation group holds selectors of its own provider", () => {
    for (const p of providerList)
      for (const g of p.rotationGroups ?? []) for (const s of g) expect(p.dkimSelectors, `${p.id} ${s}`).toContain(s);
  });

  it("finds providers by MX host and include", () => {
    expect(providersForMx("example-com.mail.protection.outlook.com").map((p) => p.id)).toEqual(["microsoft-365"]);
    expect(providersForMx("alt1.aspmx.l.google.com").map((p) => p.id)).toEqual(["google-workspace"]);
    expect(providersForMx("smtp.google.com").map((p) => p.id)).toEqual(["google-workspace"]);
    expect(providersForMx("notsmtp.google.com").map((p) => p.id)).toEqual([]);
    expect(providersForInclude("_spf.google.com").map((p) => p.id)).toEqual(["google-workspace"]);
    expect(providersForInclude("amazonses.com").map((p) => p.id)).toEqual(["amazon-ses"]);
    // Shared includes and Tucows' reseller MX name no one: Hover is named by its own MX only.
    for (const include of ["_spf.hostedemail.com", "websitewelcome.com", "spf.websitewelcome.com", "spf.webapps.net"])
      expect(providersForInclude(include), include).toEqual([]);
    expect(providersForMx("mx.name-services.com.cust.a.hostedemail.com")).toEqual([]);
    // Amazon SES receiving: an inbound-smtp MX of each documented region is SES's; another AWS
    // host, or a region the page does not list, is not.
    for (const region of ["us-east-1", "eu-west-1", "ap-southeast-3", "il-central-1"])
      expect(
        providersForMx(`inbound-smtp.${region}.amazonaws.com`).map((p) => p.id),
        region,
      ).toEqual(["amazon-ses"]);
    expect(providersForMx("inbound-smtp.xx-east-9.amazonaws.com")).toEqual([]);
    expect(providersForMx("ec2-1-2-3-4.compute-1.amazonaws.com")).toEqual([]);
    expect(rotationGroupOf("selector2")).toEqual(["selector1", "selector2"]);
    expect(rotationGroupOf("google")).toBeUndefined();
  });

  const owner = (selector: string, chain: string[] = []) => ownerOf(selector, chain)?.id;

  it("a key through a CNAME belongs to the provider of its target; Klaviyo's SendGrid account is Klaviyo", () => {
    expect(owner("kl", ["kl.domainkey.u161779.wl030.sendgrid.net"])).toBe("klaviyo");
    expect(owner("s1", ["s1.domainkey.u161779.wl030.sendgrid.net"])).toBe("klaviyo");
    expect(owner("kl2", ["kl2._domainkey.klaviyodns.com"])).toBe("klaviyo");
    expect(owner("s1", ["s1.domainkey.u1234567.wl123.sendgrid.net"])).toBe("sendgrid");
    expect(owner("k2", ["dkim2.mcsv.net"])).toBe("mailchimp");
    expect(owner("selector1", ["selector1-example-com._domainkey.example.onmicrosoft.com"])).toBe("microsoft-365");
    expect(owner("selector2", ["selector2-example-com._domainkey.example.n-v1.dkim.mail.microsoft"])).toBe(
      "microsoft-365",
    );
    // Any name of the chain counts: Strato's target is itself a CNAME into strato.de.
    expect(
      owner("strato-dkim-0002", ["strato-dkim-0002._domainkey.rzone.de", "strato-dkim-0002._domainkey.strato.de"]),
    ).toBe("strato");
    expect(owner("custom", ["custom.example.net", "s1.domainkey.u1.wl1.sendgrid.net"])).toBe("sendgrid");
  });

  // Emma's page gives e2ma-kN._domainkey CNAME e2ma-kN.dkim.e2ma.net. A provider with a target is
  // never named by the selector alone, so the same names in TXT, or towards another host, belong to
  // no one.
  it("Emma: e2ma-k1 to e2ma-k3 through its CNAME are Emma's; in TXT or elsewhere, no one's", () => {
    for (const s of ["e2ma-k1", "e2ma-k2", "e2ma-k3"]) {
      expect(owner(s, [`${s}.dkim.e2ma.net`]), s).toBe("emma");
      expect(owner(s), `${s} in TXT`).toBeUndefined();
      expect(owner(s, [`${s}.dkim.example.net`]), `${s} elsewhere`).toBeUndefined();
    }
  });

  it("a target is compared at a label boundary (xsendgrid.net is not SendGrid)", () => {
    expect(owner("s1", ["s1.domainkey.u1.wl1.xsendgrid.net"])).toBeUndefined();
    expect(owner("s1", ["sendgrid.net.example.net"])).toBeUndefined();
    expect(owner("s1", ["S1.DomainKey.U1.WL1.SendGrid.Net"])).toBe("sendgrid");
  });

  it("s1, k1, key1 and m1 in TXT, or key1 towards another host, belong to no provider", () => {
    for (const s of ["s1", "s2", "k1", "k2", "key1", "m1", "selector1"]) expect(owner(s), s).toBeUndefined();
    expect(owner("key1", ["key1.example.com.hostedemail.link"])).toBeUndefined();
    expect(owner("k1", ["k1.example.net"])).toBeUndefined();
  });

  // That holds when the provider lists no target.
  it("default, dkim and x belong to no one; a selector only one provider uses is that provider's", () => {
    // mail is also Yandex 360's, so it names no one.
    for (const s of ["default", "dkim", "x", "mail"]) expect(owner(s), s).toBeUndefined();
    expect(SELECTORS).toContain("mail");
    expect(owner("google")).toBe("google-workspace");
    expect(owner("privateemail")).toBe("namecheap-private-email");
    // smtp and mx are generic names, Mailgun's and anyone's; pic, krs and mailo only Mailgun's.
    for (const s of ["smtp", "mx"]) expect(owner(s), s).toBeUndefined();
    for (const s of ["pic", "krs", "mailo"]) expect(owner(s), s).toBe("mailgun");
    expect(owner("google", ["google.example.net"])).toBe("google-workspace");
    // MailPoet's page names its two selectors, not their target.
    expect(owner("mailpoet2", ["dkim2.sendingservice.net"])).toBe("mailpoet");
  });

  // Only when it reaches the target of a provider that lists that selector.
  it("a key under a selector tried on every check counts by its target only through its provider", () => {
    // Microsoft 365's own selector1, into its target: Microsoft's.
    expect(ownerOf("selector1", ["selector1-example-com._domainkey.example.onmicrosoft.com"])?.id).toBe(
      "microsoft-365",
    );
    // netcup's key1 is tried as Migadu's: its target names no one there.
    expect(ownerOf("key1", ["key1._domainkey.webhosting.systems"])).toBeUndefined();
    // A typed selector the check does not try on its own is still named by its target.
    expect(ownerOf("example-sf-a", ["example-sf-a.k4tyd2.custdkim.salesforce.com"])?.id).toBe("salesforce");
  });

  it("suffixes match at a label boundary and do not take another provider's hosts", () => {
    expect(providersForMx("xmx.yandex.net")).toEqual([]);
    expect(providersForMx("mx3.qq.com")).toEqual([]);
    expect(providersForMx("mx1.privateemail.com").map((p) => p.id)).toEqual(["namecheap-private-email"]);
    expect(providersForMx("mx00.ionos.com").map((p) => p.id)).toEqual(["ionos"]);
    expect(providersForMx("feedback-smtp.us-east-1.amazonses.com").map((p) => p.id)).toEqual(["amazon-ses"]);
    expect(providersForInclude("spf.privateemail.com").map((p) => p.id)).toEqual(["namecheap-private-email"]);
    expect(providersForInclude("secureserver.net").map((p) => p.id)).toEqual(["godaddy"]);
  });

  it("Namecheap Email Forwarding only receives and forwards: it is no sending service", () => {
    expect(sendingServices({ providers: ["namecheap-email-forwarding", "google-workspace"] }).map((p) => p.id)).toEqual(
      ["google-workspace"],
    );
  });
});
