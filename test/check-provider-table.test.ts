import { describe, expect, it } from "vitest";
import { emptyFields } from "../data/sources/index.ts";
import { providerList, sendingServices } from "../src/providers.ts";
import type { Finding } from "../src/types.ts";
import { byMx, check, DKIM, googleZone, P4, SOA, spfRange, withKey } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

// The provider table, each value the vendor's as data/sources/ quotes it.
// sel: a selector of the provider's own, which the check tries on every domain. A provider without
// one lists no selector, so spf-unused-include never asks about it, and its keys are found only
// under a typed selector, through a CNAME into a documented target, where it asks
// dkim-unused-provider.
// record: the whole record spf-missing writes when the page gives more than the include
// (redirect= alone, or a and mx before it).
// quiet: a provider that sends with its own return path; dkim-unused-provider never asks about it.
interface Provider {
  id: string;
  sel?: string;
  mx?: string;
  include?: string;
  target?: string;
  record?: string;
  quiet?: boolean;
}
// prettier-ignore
const PROVIDERS: Provider[] = [
  { id: "zendesk", sel: "zendesk1", target: "zendesk1._domainkey.zendesk.com", include: "mail.zendesk.com",
    quiet: true },
  { id: "mandrill", sel: "mte1", target: "dkim1.mandrillapp.com" },
  { id: "hostinger", sel: "hostingermail-a", target: "hostingermail-a.dkim.mail.hostinger.com", mx: "mx1.hostinger.com",
    include: "_spf.mail.hostinger.com" },
  { id: "ionos", sel: "s1-ionos", target: "s1.dkim.ionos.com", mx: "mx00.ionos.com" },
  { id: "gandi", sel: "gm1", target: "gm1.gandimail.net", mx: "spool.mail.gandi.net", include: "_mailcust.gandi.net" },
  { id: "migadu", sel: "key1", target: "key1.example.com._domainkey.migadu.com", mx: "aspmx1.migadu.com",
    include: "spf.migadu.com" },
  { id: "namecheap-private-email", sel: "privateemail", mx: "mx1.privateemail.com", include: "spf.privateemail.com" },
  { id: "purelymail", sel: "purelymail1", target: "key1.dkimroot.purelymail.com", mx: "mailserver.purelymail.com",
    include: "_spf.purelymail.com" },
  { id: "mailbox-org", sel: "mbo0001", target: "mbo0001._domainkey.mailbox.org", mx: "mxext1.mailbox.org",
    include: "mailbox.org" },
  // Alone, its page gives redirect=; with other senders, the include.
  { id: "strato", sel: "strato-dkim-0002", target: "strato-dkim-0002._domainkey.rzone.de", mx: "smtpin.rzone.de",
    include: "_spf.strato.com", record: "v=spf1 redirect=_spf.strato.com" },
  { id: "mailerlite", sel: "litesrv", target: "litesrv._domainkey.mlsend.com" },
  { id: "help-scout", sel: "strong1", target: "strong1._domainkey.helpscout.net" },
  { id: "constant-contact", sel: "ctct1", target: "100._domainkey.dkim1.ccsend.com" },
  { id: "squarespace", sel: "squarespace", target: "squarespace-domainkey.squarespace-mail.com" },
  // No target in its page, so attributed by its selector's name; no MX or include, so never asked
  // about.
  { id: "mailpoet", sel: "mailpoet2", target: "dkim2.sendingservice.net" },
  { id: "klaviyo", sel: "kl", target: "kl.domainkey.u161779.wl030.sendgrid.net" },
  { id: "sendgrid", sel: "s1", target: "s1.domainkey.u1234567.wl123.sendgrid.net", quiet: true },
  // Mailgun signs with the root's key and sends from a subdomain, whose SPF the apex never shows
  // (its DNS FAQ, “DKIM authority”), so dkim-unused-provider never asks about it.
  { id: "mailgun", sel: "krs", mx: "mxa.mailgun.org", include: "mailgun.org", quiet: true },
  { id: "microsoft-365", sel: "selector1", target: "selector1-example-com._domainkey.example.onmicrosoft.com",
    include: "spf.protection.outlook.com" },
  { id: "fastmail", sel: "fm1", target: "fm1.example.com.dkim.fmhosted.com", include: "spf.messagingengine.com" },
  { id: "icloud", sel: "sig1", target: "sig1.dkim.example.com.at.icloudmailadmin.com", include: "icloud.com" },
  { id: "yandex-360", mx: "mx.yandex.net", include: "_spf.yandex.net", record: "v=spf1 redirect=_spf.yandex.net" },
  { id: "tencent-exmail", mx: "mxbiz1.qq.com", include: "spf.mail.qq.com" },
  { id: "alibaba-mail", mx: "mx1.qiye.aliyun.com", include: "spf.qiye.aliyun.com" },
  { id: "alibaba-mail", mx: "mxw.mxhichina.com", include: "spf.qiye.aliyun.com" },
  { id: "ovhcloud", mx: "mx1.mail.ovh.net", include: "mx.ovh.com",
    target: "ovhmo3456789-selector1._domainkey.123403.aj.dkim.mail.ovh.net" },
  { id: "vk-workspace", mx: "emx.mail.ru", include: "_spf.mail.ru", record: "v=spf1 redirect=_spf.mail.ru" },
  { id: "rackspace", mx: "mx1.emailsrvr.com", include: "emailsrvr.com" },
  { id: "salesforce", include: "_spf.salesforce.com", target: "example-sf-a.k4tyd2.custdkim.salesforce.com" },
  { id: "aruba", include: "_spf.aruba.it" },
  // Named by its MX only, as spf.webapps.net is shared by several hosts: the fix still writes the
  // include its page gives.
  { id: "register-nominalia", mx: "mail.register.it", record: "v=spf1 include:spf.webapps.net ~all",
    target: "key-nomi001._domainkey.securemail.pro" },
  { id: "infomaniak", mx: "mta-gw.infomaniak.ch", include: "spf.infomaniak.ch" },
  { id: "locaweb", mx: "mx.core.locaweb.com.br", include: "_spf.locaweb.com.br" },
  { id: "transip", mx: "mx.transip.email", include: "_spf.transip.email", target: "_dkim-A.transip.email" },
  { id: "netcup", include: "_spf.webhosting.systems", target: "key1._domainkey.webhosting.systems" },
  // The pages of ALL-INKL and Mijndomein give a and mx before the include: the customer's own
  // server is the MX host, outside the include.
  { id: "all-inkl", mx: "w0123456.kasserver.com", include: "spf.kasserver.com",
    record: "v=spf1 a mx include:spf.kasserver.com ~all" },
  { id: "cyber-folks", include: "_spf.cyberfolks.pl" },
  { id: "godaddy", mx: "smtp.secureserver.net", include: "secureserver.net" },
  { id: "godaddy", mx: "mailstore1.secureserver.net", include: "secureserver.net" },
  { id: "arsys", include: "_spf.serviciodecorreo.es" },
  { id: "hostnet", include: "_spf.hostnet.nl" },
  { id: "antagonist", include: "_spf.webhostingserver.nl",
    target: "abcdef12345hijklmnop.whs1.dkim.webhostingserver.nl" },
  { id: "namecheap-email-forwarding", include: "spf.efwd.registrar-servers.com" },
  { id: "marketo", include: "mktomail.com" },
  { id: "elastic-email", include: "_spf.elasticemail.com" },
  { id: "mailchannels", include: "relay.mailchannels.net" },
  { id: "activecampaign", include: "emsd1.com" },
  { id: "host-europe", include: "spf.server-he.de" },
  { id: "o2switch", include: "spf.jabatus.fr" },
  { id: "kinghost", include: "_spf.kinghost.net" },
  { id: "kinghost", include: "_spf.uni5.net" },
  { id: "mijndomein", mx: "mx1.mijndomein.nl", include: "spf.mijndomeinhosting.nl",
    record: "v=spf1 a mx include:spf.mijndomeinhosting.nl ~all" },
  { id: "mimecast", include: "us._netblocks.mimecast.com" },
  { id: "barracuda", include: "spf.ess.uk.barracudanetworks.com" },
  { id: "hornetsecurity", include: "spf.hornetsecurity.com" },
];
// A security gateway's MX says it filters incoming mail, so spf-missing writes no include for it;
// its own include in the SPF names it.
const GATEWAYS: [string, string][] = [
  ["mimecast", "eu-smtp-inbound-1.mimecast.com"],
  ["mimecast", "za-smtp-inbound-2.mimecast.co.za"],
  ["mimecast", "je-smtp-inbound-1.mimecast-offshore.com"],
  ["barracuda", "d123456a.ess.barracudanetworks.com"],
  ["barracuda", "d123456.a.ess.de.barracudanetworks.com"],
  ["barracuda", "d123456.a.ess.uk.barracudanetworks.com"],
  ["barracuda", "d123456.a.ess.au.barracudanetworks.com"],
  ["hornetsecurity", "mx03.hornetsecurity.com"],
  ["cisco-secure-email", "mx1.hc1234-56.iphmx.com"],
  ["cisco-secure-email", "mx1.hc1234-56.eu.iphmx.com"],
];

/** The ids of the services that send as the domain, as sendingServices gives them. */
const sending = async (z: Zone) => sendingServices(await check(z)).map((p) => p.id);

/** One case per include: a provider named by two MX hosts has two rows with the same include. */
const oncePerInclude = (cs: Provider[]) => [...new Map(cs.map((c) => [c.include, c])).values()];

describe("each provider's MX, include and DKIM target", () => {
  for (const c of PROVIDERS.filter((x): x is Provider & { sel: string } => x.sel !== undefined)) {
    it(`${c.id}: a key at ${c.sel} is attributed to it`, async () => {
      const r = await check(withKey(c.sel, c.target));
      expect(r.providers).toEqual(["google-workspace", c.id]);
      // A key needs an MX or include to compare with, and a provider that sends with its own
      // return path is never asked about by dkim-unused-provider.
      const asks = !c.quiet && (c.mx !== undefined || c.include !== undefined);
      const q = r.findings.find((f) => f.id === "dkim-unused-provider");
      if (asks) expect(q?.found).toBe(`${c.sel}._domainkey`);
      else expect(q).toBeUndefined();
    });
  }

  for (const c of oncePerInclude(PROVIDERS.filter((x) => x.include && x.sel))) {
    it(`${c.id}: include:${c.include} with no key and no MX asks spf-unused-include`, async () => {
      const z = googleZone();
      const include = c.include as string;
      (z["example.com"] as Node).TXT = [`v=spf1 include:_spf.google.com include:${include} ~all`];
      z[include] = spfRange();
      const r = await check(z);
      expect(r.findings.find((f) => f.id === "spf-unused-include")?.found).toBe(`include:${include}`);
      // A live key at one of its selectors answers the question, attributed or not.
      const keyed = await check({ ...z, [`${c.sel}._domainkey.example.com`]: { TXT: [DKIM] } });
      expect(ids(keyed)).not.toContain("spf-unused-include");
    });
  }

  for (const c of PROVIDERS.filter((x) => x.mx)) {
    const fix = c.record ?? (c.include ? `v=spf1 include:${c.include} ~all` : undefined);
    it(`${c.id}: no SPF on a domain with MX ${c.mx}: ${fix ?? "no include to write"}`, async () => {
      const r = await check(byMx(c.mx as string));
      expect(r.mx[0]?.provider).toBe(c.id);
      const f = r.findings.find((x) => x.id === "spf-missing") as Finding;
      expect(f.fixes.map((x) => x.value)).toEqual(fix ? [fix] : []);
    });
  }

  for (const c of oncePerInclude(PROVIDERS.filter((x) => x.include && !x.sel))) {
    // The provider lists no selector, so spf-unused-include cannot ask about it.
    it(`${c.id}: include:${c.include} next to Google Workspace is seen and asks nothing`, async () => {
      const z = googleZone();
      const include = c.include as string;
      (z["example.com"] as Node).TXT = [`v=spf1 include:_spf.google.com include:${include} ~all`];
      z[include] = spfRange();
      const r = await check(z);
      expect(r.providers).toEqual(["google-workspace", c.id]);
      expect(ids(r)).not.toContain("spf-unused-include");
    });
  }

  for (const c of PROVIDERS.filter((x) => x.target && !x.sel)) {
    // dkim-unused-provider asks whether the provider still sends.
    it(`${c.id}: a key at a typed selector through ${c.target} is its own and asked about`, async () => {
      const z = googleZone();
      const target = c.target as string;
      Object.assign(z, { "custom._domainkey.example.com": { CNAME: [target] }, [target]: { TXT: [DKIM] } });
      const r = await check(z, "example.com", { extraSelectors: ["custom"] });
      expect(r.providers).toEqual(["google-workspace", c.id]);
      expect(r.findings.find((f) => f.id === "dkim-unused-provider")?.found).toBe("custom._domainkey");
    });
  }

  // Salesforce's selectors are the customer's, and many pick one the check tries on every domain. A
  // key there names no provider by its target, so no question pushes to delete a key in use. Six
  // domains with records shaped like those found next to such keys: an MX at Google, Cisco,
  // Proofpoint or Microsoft 365, an SPF record with macros, many includes or ip4 terms, and a
  // target with the token of Salesforce's own example; the key is the helpers' own.
  const SALESFORCE_SETUPS: { domain: string; mx: string; spf: string; sel: string; target: string }[] = [
    {
      domain: "example.com",
      mx: "aspmx.l.google.com",
      spf: "v=spf1 include:_spf.example.com -all",
      sel: "default",
      target: "default.k4tyd2.custdkim.salesforce.com",
    },
    {
      domain: "example.net",
      mx: "mx1.hc1234-56.iphmx.com",
      spf: "v=spf1 exists:%{i}._i.%{d}._d.espf.agari-dns.net include:%{d}.0a.spf-protect.agari-dns.net ~all",
      sel: "selector1",
      target: "selector1.k4tyd2.custdkim.salesforce.com",
    },
    {
      domain: "example.org",
      mx: "mxa-00123456.gslb.pphosted.com",
      spf: "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      sel: "dkim",
      target: "dkim.k4tyd2.custdkim.salesforce.com",
    },
    {
      domain: "brand.example",
      mx: "mxa-00654321.gslb.pphosted.com",
      spf: "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all",
      sel: "s1",
      target: "s1.k4tyd2.custdkim.salesforce.com",
    },
    {
      domain: "campus.example",
      mx: "campus-example.mail.protection.outlook.com",
      spf: "v=spf1 include:spf.protection.outlook.com include:spf1.example.net include:spf2.example.net include:spf3.example.net ip4:192.0.2.208 ip4:192.0.2.224 ip4:198.51.100.250 -all",
      sel: "key1",
      target: "key1.k4tyd2.custdkim.salesforce.com",
    },
    {
      domain: "school.example",
      mx: "mx1.hc1234-56.iphmx.com",
      spf: "v=spf1 include:spf1.example.net include:_spf.google.com include:mail.zendesk.com include:amazonses.com include:spf2.example.net include:spf3.example.net include:emsd1.com ip4:192.0.2.201 ip4:198.51.100.18 ip4:203.0.113.102 ip4:203.0.113.123 ~all",
      sel: "key1",
      target: "key1.k4tyd2.custdkim.salesforce.com",
    },
  ];
  for (const c of SALESFORCE_SETUPS) {
    // The selector is one the check tries on every domain.
    it(`${c.domain}: a Salesforce key under ${c.sel} names no provider and asks nothing`, async () => {
      const z: Zone = {
        [c.domain]: { SOA, MX: [`10 ${c.mx}`], TXT: [c.spf] },
        [c.mx]: { A: [P4] },
        [`${c.sel}._domainkey.${c.domain}`]: { CNAME: [c.target] },
        [c.target]: { TXT: [DKIM] },
        [`_dmarc.${c.domain}`]: { TXT: ["v=DMARC1; p=reject;"] },
      };
      const r = await check(z, c.domain);
      expect(r.dkim.keys.map((k) => k.selector)).toContain(c.sel);
      expect(r.providers).not.toContain("salesforce");
      expect(ids(r)).not.toContain("dkim-unused-provider");
    });
  }

  for (const [id, mx] of GATEWAYS) {
    // The gateway gets no include of its own.
    it(`${id}, a security gateway, by MX ${mx}: only the include of the mailbox behind it`, async () => {
      const r = await check(byMx(mx));
      expect(r.mx[0]?.provider).toBe(id);
      expect(r.findings.find((x) => x.id === "spf-missing")?.fixes).toEqual([]);
      // In front of Microsoft 365, the fix writes Microsoft's include only.
      const z = byMx(mx);
      (z["example.com"] as Node).MX = [`10 ${mx}`, "20 example-com.mail.protection.outlook.com"];
      z["example-com.mail.protection.outlook.com"] = { A: [P4] };
      const both = await check(z);
      expect(both.findings.find((x) => x.id === "spf-missing")?.fixes.map((x) => x.value)).toEqual([
        "v=spf1 include:spf.protection.outlook.com ~all",
      ]);
    });
  }

  it("Strato next to another sender by MX gets its include, never redirect=", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["10 smtpin.rzone.de", "20 smtp.google.com"] },
      "smtpin.rzone.de": { A: [P4] },
      "smtp.google.com": { A: [P4] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    };
    const r = await check(z);
    const f = r.findings.find((x) => x.id === "spf-missing") as Finding;
    expect(f.fixes.map((x) => x.value)).toEqual(["v=spf1 include:_spf.google.com include:_spf.strato.com ~all"]);
  });

  it("Hetzner: an MX under your-server.de is Hetzner's, with no include to write", async () => {
    const r = await check(byMx("www123.your-server.de"));
    expect(r.mx[0]?.provider).toBe("hetzner");
    expect(r.findings.find((x) => x.id === "spf-missing")?.fixes).toEqual([]);
  });

  // _spf.hostedemail.com is the include of every Tucows reseller (customers of eNom, Lycos and
  // Name.com use it too), so it never names Hover; Hover's own MX does, and a domain with it
  // and no SPF gets the include Hover's page gives.
  // The fix still writes that include.
  it("Hover: named by its own MX only; the shared Tucows include names no one", async () => {
    const r = await check(byMx("mx.hover.com.cust.hostedemail.com"));
    expect(r.mx[0]?.provider).toBe("hover");
    expect(r.findings.find((x) => x.id === "spf-missing")?.fixes.map((x) => x.value)).toEqual([
      "v=spf1 include:_spf.hostedemail.com ~all",
    ]);
    // The include it writes is the one Hover's page gives, quoted in data/sources/.
    expect(emptyFields.find((f) => f.provider === "hover" && f.field === "spfIncludes")?.documented).toBe(
      providerList.find((p) => p.id === "hover")?.fixInclude,
    );
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:_spf.hostedemail.com ~all"];
    z["_spf.hostedemail.com"] = spfRange();
    expect((await check(z)).providers).toEqual(["google-workspace"]);
  });

  // An include several brands give names none of them, as Hover's.
  it("websitewelcome.com and spf.webapps.net, shared by several hosts, name no one", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com include:websitewelcome.com ~all"];
    z["websitewelcome.com"] = spfRange();
    expect((await check(z)).providers).toEqual(["google-workspace"]);
  });

  // MX hosts under ionos.de, ionos.es, 1and1.es and 1and1.fr.
  it("IONOS Germany, Spain and France: those MX hosts are IONOS's and get no include", async () => {
    for (const mx of ["mx00.ionos.de", "mx00.ionos.es", "mx01.1and1.es", "mx00.1and1.fr"]) {
      const r = await check(byMx(mx));
      expect(r.mx[0]?.provider, mx).toBe("ionos");
      expect(r.findings.find((x) => x.id === "spf-missing")?.fixes, mx).toEqual([]);
    }
  });

  it("Amazon SES receiving: an inbound-smtp MX is SES's, and its fix writes no include", async () => {
    // A receiving MX says nothing of sending, so the fix writes no include for it; the MX of a
    // MAIL FROM domain under amazonses.com still gets it.
    const r = await check(byMx("inbound-smtp.eu-west-1.amazonaws.com"));
    expect(r.mx[0]?.provider).toBe("amazon-ses");
    expect(r.findings.find((x) => x.id === "spf-missing")?.fixes).toEqual([]);
    const sending = await check(byMx("feedback-smtp.eu-west-1.amazonses.com"));
    expect(sending.findings.find((x) => x.id === "spf-missing")?.fixes.map((x) => x.value)).toEqual([
      "v=spf1 include:amazonses.com ~all",
    ]);
  });

  // sendingServices counts the services that send as the domain. An MX that says nothing of sending
  // (a security gateway, an SES receiving endpoint) does not make one, unless the SPF or a DKIM key
  // shows the same provider too. Hetzner hosts mailboxes, which send.
  it("a gateway or an SES receiving MX alone is no sending service; with SES's include, SES is", async () => {
    for (const [, mx] of GATEWAYS) expect(await sending(byMx(mx)), mx).toEqual([]);
    const z = byMx("eu-smtp-inbound-1.mimecast.com");
    (z["example.com"] as Node).MX = ["10 eu-smtp-inbound-1.mimecast.com", "20 example-com.mail.protection.outlook.com"];
    z["example-com.mail.protection.outlook.com"] = { A: [P4] };
    expect(await sending(z)).toEqual(["microsoft-365"]);
    const ses = byMx("inbound-smtp.eu-west-1.amazonaws.com");
    expect(await sending(ses)).toEqual([]);
    (ses["example.com"] as Node).TXT = ["v=spf1 include:amazonses.com ~all"];
    ses["amazonses.com"] = spfRange();
    expect(await sending(ses)).toEqual(["amazon-ses"]);
    expect(await sending(byMx("www123.your-server.de"))).toEqual(["hetzner"]);
  });
});
