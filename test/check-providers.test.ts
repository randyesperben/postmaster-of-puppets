// The two questions the check asks about providers (spf-unused-include and dkim-unused-provider)
// and the services that send as the domain (sendingServices), through full checks: when a key or an
// include raises a question, and the cases that ask nothing. Each provider's own cases, row by
// row, are in check-provider-table.test.ts.
import { describe, expect, it } from "vitest";
import { sendingServices } from "../src/providers.ts";
import { byMx, check, DKIM, googleZone, P4, SOA, spfRange, withKey } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

/** The ids of the services that send as the domain, as sendingServices gives them. */
const sending = async (z: Zone) => sendingServices(await check(z)).map((p) => p.id);

describe("providers and the two questions", () => {
  it("spf-unused-include: an include of a provider seen nowhere else", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"];
    z["spf.protection.outlook.com"] = spfRange();
    const r = await check(z);
    const q = r.findings.find((f) => f.id === "spf-unused-include");
    expect(q?.vars).toEqual({ provider: "Microsoft 365" });
    expect(q?.fixes).toEqual([]);
    expect(r.verdict).toBe("protected");
    expect(r.providers).toEqual(["google-workspace", "microsoft-365"]);
  });

  // A host's include can hold Google's and Microsoft's though the domain wrote neither, as
  // websitewelcome.com does. Only an include or redirect of the domain's own record is asked about.
  it("spf-unused-include asks only about what the domain's own record names", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:hosting.example.net ~all"];
    z["hosting.example.net"] = { TXT: ["v=spf1 include:spf.protection.outlook.com ~all"] };
    z["spf.protection.outlook.com"] = spfRange();
    const r = await check(z);
    // Still seen: the domain's SPF does authorize it.
    expect(r.providers).toEqual(["google-workspace", "microsoft-365"]);
    expect(ids(r)).not.toContain("spf-unused-include");
    // A redirect is the domain's own record too, and the question shows it as written.
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com redirect=spf.protection.outlook.com"];
    expect((await check(z)).findings.find((f) => f.id === "spf-unused-include")?.found).toBe(
      "redirect=spf.protection.outlook.com",
    );
  });

  it("dkim-unused-provider: a key of a provider seen nowhere else", async () => {
    const z = googleZone();
    // Fastmail publishes its keys by CNAME, so only its target says the key is Fastmail's.
    z["fm1._domainkey.example.com"] = { CNAME: ["fm1.example.com.dkim.fmhosted.com"] };
    z["fm1.example.com.dkim.fmhosted.com"] = { TXT: [DKIM] };
    const r = await check(z);
    const q = r.findings.find((f) => f.id === "dkim-unused-provider");
    expect(q?.vars).toEqual({ provider: "Fastmail" });
    expect(q?.found).toBe("fm1._domainkey");
    expect(r.delivery).toBe("ok");
  });
});

describe("providers: the cases that ask nothing", () => {
  it("a selector two providers share (k1) says nothing about either", async () => {
    const z = googleZone();
    z["k1._domainkey.example.com"] = { TXT: [DKIM] };
    const r = await check(z);
    expect(r.providers).toEqual(["google-workspace"]);
    expect(ids(r)).not.toContain("dkim-unused-provider");
  });

  it("a provider whose selectors are secret (Amazon SES) is never asked about", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:amazonses.com ~all"];
    z["amazonses.com"] = spfRange();
    const r = await check(z);
    expect(r.providers).toContain("amazon-ses");
    expect(ids(r)).not.toContain("spf-unused-include");
  });

  it("a key whose provider is in SPF is no question", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:spf.messagingengine.com ~all"];
    z["spf.messagingengine.com"] = spfRange();
    z["fm1._domainkey.example.com"] = { CNAME: ["fm1.example.com.dkim.fmhosted.com"] };
    z["fm1.example.com.dkim.fmhosted.com"] = { TXT: [DKIM] };
    const r = await check(z);
    expect(r.providers).toContain("fastmail");
    expect(ids(r)).not.toContain("dkim-unused-provider");
    expect(ids(r)).not.toContain("spf-unused-include");
  });
});

// The questions a key or an include raises next to the rest of the domain, for providers with
// selectors of their own.
describe("keys and includes of providers with selectors of their own", () => {
  // An Easy DKIM key has a token for selector, so only a selector the caller passes finds it; its
  // CNAME into amazonses.com makes it SES's, and SES, which sends from a subdomain, is never asked
  // about.
  it("a key at a typed selector, by CNAME into amazonses.com, is Amazon SES's and asks nothing", async () => {
    const z = googleZone();
    const target = "abc123token.dkim.us-west-2.amazonses.com";
    Object.assign(z, { "abc123token._domainkey.example.com": { CNAME: [target] }, [target]: { TXT: [DKIM] } });
    const r = await check(z, "example.com", { extraSelectors: ["abc123token"] });
    expect(r.dkim.keys.map((k) => k.selector)).toEqual(["google", "abc123token"]);
    expect(r.providers).toEqual(["google-workspace", "amazon-ses"]);
    expect(ids(r)).not.toContain("dkim-unused-provider");
  });

  it("a SendGrid s1 key, an intercom key or a Mailgun key in TXT with no include asks nothing", async () => {
    // smtp and mx are generic: a key there in TXT, next to Google Workspace, does not ask whether
    // Mailgun still sends.
    expect(ids(await check(withKey("s1", "s1.domainkey.u1.wl1.sendgrid.net")))).not.toContain("dkim-unused-provider");
    for (const sel of ["intercom", "smtp", "mx", "pic", "krs", "mailo"])
      expect(ids(await check(withKey(sel))), sel).not.toContain("dkim-unused-provider");
  });

  // Mailgun's pages give no CNAME target for smtp or mx (the only one, “something like
  // pdk1._domainkey.9d876.dkim1.mailgun.com”, is for its pdk1 and pdk2 selectors), so a key there
  // belongs to no one, by TXT or by CNAME.
  it("a key at smtp or mx, in TXT or through a CNAME into Mailgun, names no provider", async () => {
    for (const sel of ["smtp", "mx"]) {
      for (const target of [
        undefined,
        `${sel}._domainkey.abc1234.dkim1.us.mgsend.org`,
        `${sel}.example.com.mailgun.org`,
      ]) {
        const r = await check(withKey(sel, target));
        expect(r.providers, `${sel} ${target ?? "TXT"}`).toEqual(["google-workspace"]);
        expect(
          r.dkim.keys.map((k) => k.selector),
          `${sel} ${target ?? "TXT"}`,
        ).toEqual(["google", sel]);
      }
    }
  });

  it("a key at pic, krs or mailo in TXT is still Mailgun's", async () => {
    for (const sel of ["pic", "krs", "mailo"])
      expect((await check(withKey(sel))).providers, sel).toEqual(["google-workspace", "mailgun"]);
  });

  it("include:mailgun.org with a live key only at smtp or mx asks nothing", async () => {
    for (const sel of ["smtp", "mx"]) {
      const z = withKey(sel);
      (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:mailgun.org ~all"];
      z["mailgun.org"] = spfRange();
      const r = await check(z);
      expect(r.providers, sel).toEqual(["google-workspace", "mailgun"]);
      expect(ids(r), sel).not.toContain("spf-unused-include");
    }
  });

  it("a Google key with no Google MX or include still asks", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["10 mx.example.com"], TXT: ["v=spf1 ip4:192.0.32.10 -all"] },
      "mx.example.com": { A: [P4] },
      "google._domainkey.example.com": { TXT: [DKIM] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    };
    const r = await check(z);
    expect(r.findings.find((f) => f.id === "dkim-unused-provider")).toMatchObject({
      found: "google._domainkey",
      vars: { provider: "Google Workspace" },
    });
  });

  it("include:sendgrid.net next to a key at m1 asks nothing", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"];
    z["sendgrid.net"] = spfRange();
    z["m1._domainkey.example.com"] = { TXT: [DKIM] };
    const r = await check(z);
    expect(r.providers).toEqual(["google-workspace", "sendgrid"]);
    expect(ids(r)).not.toContain("spf-unused-include");
  });

  it("keys at s1, k1, key1 and m1 in TXT name no provider", async () => {
    const z = googleZone();
    for (const s of ["s1", "k1", "key1", "m1"]) z[`${s}._domainkey.example.com`] = { TXT: [DKIM] };
    const r = await check(z);
    expect(r.providers).toEqual(["google-workspace"]);
    expect(ids(r)).not.toContain("dkim-unused-provider");
  });

  it("a key whose target only looks like SendGrid's (xsendgrid.net) names no provider", async () => {
    const r = await check(withKey("s1", "s1.domainkey.u1.wl1.xsendgrid.net"));
    expect(r.providers).toEqual(["google-workspace"]);
  });

  it("Mailchimp, whose page asks for no SPF, is never asked about", async () => {
    const r = await check(withKey("k2", "dkim2.mcsv.net"));
    expect(r.providers).toEqual(["google-workspace", "mailchimp"]);
    expect(ids(r)).not.toContain("dkim-unused-provider");
  });
});

describe("questions and sending services next to the rest of the domain", () => {
  // Nominalia's page gives include:spf.webapps.net and key-nomi001 into securemail.pro, and no MX.
  // Its include names no one, but when it is in the SPF tree it is the provider's own fix: a key of
  // the same provider asks nothing, whatever the MX.
  it("a Register.it and Nominalia key with spf.webapps.net in the SPF asks nothing, whatever the MX", async () => {
    for (const mx of ["mx.example.net", "mail.register.it"]) {
      const z: Zone = {
        "example.com": { SOA, MX: [`10 ${mx}`], TXT: ["v=spf1 include:spf.webapps.net ~all"] },
        [mx]: { A: [P4] },
        "spf.webapps.net": spfRange(),
        "key-nomi001._domainkey.example.com": { CNAME: ["key-nomi001._domainkey.securemail.pro"] },
        "key-nomi001._domainkey.securemail.pro": { TXT: [DKIM] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=none; rua=mailto:d@example.com"] },
      };
      const r = await check(z, "example.com", { extraSelectors: ["key-nomi001"] });
      expect(r.providers, mx).toContain("register-nominalia");
      expect(ids(r), mx).not.toContain("dkim-unused-provider");
    }
  });

  // A SendGrid key under a selector tried on every check names no provider, but its CNAME into
  // sendgrid.net still shows SendGrid signs, so include:sendgrid.net is not asked about.
  // It holds under any selector.
  it("a live key whose CNAME reaches SendGrid's target answers its include's question", async () => {
    for (const sel of ["cm", "mail", "default"]) {
      const z = googleZone();
      (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"];
      z["sendgrid.net"] = spfRange();
      z[`${sel}._domainkey.example.com`] = { CNAME: [`${sel}.domainkey.u123.wl001.sendgrid.net`] };
      z[`${sel}.domainkey.u123.wl001.sendgrid.net`] = { TXT: [DKIM] };
      expect(ids(await check(z)), sel).not.toContain("spf-unused-include");
    }
    // With no key reaching SendGrid, the question stays.
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"];
    z["sendgrid.net"] = spfRange();
    expect(ids(await check(z))).toContain("spf-unused-include");
  });

  // A gateway whose own documented include is in the SPF sends for the domain, so sendingServices
  // counts it; the fix of spf-missing still never writes it (the GATEWAYS cases of
  // check-provider-table.test.ts).
  it("a gateway with its documented include in the SPF is a sending service", async () => {
    const withInclude: [string, string, string][] = [
      ["mimecast", "eu-smtp-inbound-1.mimecast.com", "eu._netblocks.mimecast.com"],
      ["mimecast", "eu-smtp-inbound-1.mimecast.com", "_netblocks.mimecast.com"],
      ["barracuda", "d123456.a.ess.de.barracudanetworks.com", "spf.ess.de.barracudanetworks.com"],
      ["barracuda", "d123456a.ess.barracudanetworks.com", "spf.ess.barracudanetworks.com"],
      ["hornetsecurity", "mx03.hornetsecurity.com", "spf.hornetsecurity.com"],
    ];
    for (const [id, mx, include] of withInclude) {
      const z = byMx(mx);
      (z["example.com"] as Node).TXT = [`v=spf1 include:${include} ~all`];
      z[include] = spfRange();
      expect(await sending(z), include).toEqual([id]);
    }
  });

  // What a shared host include holds is the host's. websitewelcome.com (HostGator in the US,
  // Bluehost) includes Google's and Microsoft's, which do not make the domain a customer of either.
  it("providers inside a shared host include are the host's, not the domain's", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["0 mail.example.com"], TXT: ["v=spf1 a mx include:websitewelcome.com ~all"] },
      "mail.example.com": { A: [P4] },
      "websitewelcome.com": {
        TXT: ["v=spf1 ip4:192.0.32.0/24 include:_spf.google.com include:spf.protection.outlook.com ~all"],
      },
      "_spf.google.com": spfRange(),
      "spf.protection.outlook.com": spfRange(),
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    };
    const r = await check(z);
    expect(r.providers).toEqual([]);
    expect(sendingServices(r)).toEqual([]);
    // The domain's own wrapper is not shared: what it holds is still the domain's.
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.example.com ~all"];
    z["_spf.example.com"] = { TXT: ["v=spf1 include:_spf.google.com ~all"] };
    expect((await check(z)).providers).toEqual(["google-workspace"]);
  });
});
