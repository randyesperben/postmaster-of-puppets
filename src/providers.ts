// Mail providers and DKIM selectors, checked on 2026-11-18 and 2026-11-19 against each vendor's
// documentation or by DoH on the vendor's own domain. One file, so the checks and the fixes read
// the same data. The source of each value sits in the sources folder, which the engine never
// imports. A provider is here for what the engine uses: a dkimTargets suffix, or the MX and
// include of the apex as its page gives them. Postmark and HostGator Brasil publish none of
// these, so their entries recognize nothing and only document the provider.
import { isAtOrBelow } from "./dns/names.ts";
import type { Provider, Report } from "./types.ts";

/**
 * The Regions where Amazon SES receives email, as its endpoints page lists them (sources folder).
 */
export const SES_RECEIVING_REGIONS: readonly string[] = (
  "us-east-1 us-east-2 us-west-1 us-west-2 af-south-1 ap-southeast-3 ap-south-1 ap-northeast-3 ap-northeast-2 ap-southeast-1 " +
  "ap-southeast-2 ap-northeast-1 ca-central-1 eu-central-1 eu-west-1 eu-west-2 eu-south-1 eu-west-3 eu-north-1 il-central-1 me-south-1 sa-east-1"
).split(" ");

/**
 * The email providers the engine recognizes, with the MX hosts, SPF includes, DKIM selectors and
 * key targets their documentation gives, or that DNS shows on the vendor's own domains.
 * A provider with few values sits on one line, so the table reads one provider per line; Prettier
 * leaves it as written.
 */
// prettier-ignore
export const providerList: readonly Readonly<Provider>[] = [
  {
    id: "google-workspace",
    name: "Google Workspace",
    mx: ["smtp.google.com", "aspmx.l.google.com"],
    spfIncludes: ["_spf.google.com"],
    dkimSelectors: ["google"],
  },
  {
    id: "microsoft-365",
    name: "Microsoft 365",
    mx: ["mail.protection.outlook.com", "mx.microsoft"],
    spfIncludes: ["spf.protection.outlook.com"],
    dkimSelectors: ["selector1", "selector2"],
    dkimTargets: ["onmicrosoft.com", "dkim.mail.microsoft"],
    // Only the active selector's CNAME target exists at any time (DoH on microsoft.com, github.com
    // and xbox.com, 2026-11-18), so the other one dangling is expected.
    rotationGroups: [["selector1", "selector2"]],
  },
  {
    id: "fastmail",
    name: "Fastmail",
    mx: ["messagingengine.com"],
    spfIncludes: ["spf.messagingengine.com"],
    dkimSelectors: ["fm1", "fm2", "fm3"],
    dkimTargets: ["dkim.fmhosted.com"],
  },
  {
    id: "zoho-mail",
    name: "Zoho Mail",
    mx: ["zoho.com", "zoho.eu"],
    spfIncludes: ["zohomail.com", "one.zoho.com"],
    dkimSelectors: ["zoho"],
  },
  {
    id: "proton-mail",
    name: "Proton Mail",
    mx: ["protonmail.ch"],
    spfIncludes: ["_spf.protonmail.ch"],
    dkimSelectors: ["protonmail", "protonmail2", "protonmail3"],
  },
  {
    id: "icloud",
    name: "iCloud+",
    mx: ["mail.icloud.com"],
    spfIncludes: ["icloud.com"],
    dkimSelectors: ["sig1"],
    dkimTargets: ["at.icloudmailadmin.com"],
  },
  {
    id: "cloudflare-email-routing",
    name: "Cloudflare Email Routing",
    mx: ["mx.cloudflare.net"],
    spfIncludes: ["_spf.mx.cloudflare.net"],
    dkimSelectors: ["cf2024-1"],
    // Its records at the apex "route incoming emails to Cloudflare and authenticate forwarded
    // emails"; sending as the domain is Email Sending, on records of a cf-bounce. subdomain
    // (developers.cloudflare.com/email-service/configuration/domains/, read 2026-11-19).
    receiveOnly: true,
  },
  {
    id: "amazon-ses",
    name: "Amazon SES",
    // Its MAIL FROM MX, then the receiving endpoint of each Region its page lists (2026-11-24).
    mx: ["amazonses.com", ...SES_RECEIVING_REGIONS.map((r) => `inbound-smtp.${r}.amazonaws.com`)],
    // A receiving endpoint says the domain receives through SES, not that it sends through it, so
    // spf-missing writes include:amazonses.com only for the MAIL FROM one.
    sendingMx: ["amazonses.com"],
    spfIncludes: ["amazonses.com"],
    dkimSelectors: [], // Easy DKIM selectors are random tokens
    // A key a user finds under a selector they type is SES's by its CNAME.
    dkimTargets: ["amazonses.com"],
    // Its MAIL FROM is a subdomain, of amazonses.com or of the sender's: the apex shows no SES.
    sendOnly: true,
  },
  {
    id: "sendgrid",
    name: "SendGrid",
    mx: ["sendgrid.net"],
    spfIncludes: ["sendgrid.net"],
    dkimSelectors: ["s1", "s2", "m1"],
    dkimTargets: ["sendgrid.net"],
    sendOnly: true,
  },
  {
    id: "mailgun",
    name: "Mailgun",
    mx: ["mailgun.org"],
    spfIncludes: ["mailgun.org"],
    // smtp and mx stay in the list, so a live key there answers spf-unused-include, but they are
    // GENERIC_SELECTORS: a key under them is never Mailgun's by the name alone.
    dkimSelectors: ["smtp", "mx", "pic", "krs", "mailo"],
    // Its key sits at the root by default while the mail goes out from a sending subdomain, whose
    // SPF the apex never shows (sources folder).
    sendOnly: true,
  },
  // Its DKIM record, name included, is shown in the account, and its Return-Path is a CNAME.
  {
    id: "postmark",
    name: "Postmark",
    mx: [],
    spfIncludes: [],
    dkimSelectors: [],
  },
  {
    id: "resend",
    name: "Resend",
    mx: [],
    spfIncludes: [],
    dkimSelectors: ["resend"],
  },
  {
    id: "brevo",
    name: "Brevo",
    mx: [],
    spfIncludes: [],
    // Not "mail": Yandex 360 uses it too, and it names no one, like default (sources folder).
    dkimSelectors: ["brevo1", "brevo2"],
  },
  {
    id: "mailchimp",
    name: "Mailchimp",
    mx: [],
    spfIncludes: [], // its page asks for two CNAME and the DMARC TXT, no SPF
    dkimSelectors: ["k1", "k2", "k3"],
    dkimTargets: ["mcsv.net"],
  },
  {
    id: "klaviyo",
    name: "Klaviyo",
    mx: [],
    spfIncludes: [],
    dkimSelectors: ["kl", "kl2", "kl1"],
    // Its legacy selectors point into one SendGrid account; this longer suffix beats sendgrid.net.
    dkimTargets: ["u161779.wl030.sendgrid.net", "klaviyodns.com"],
  },
  {
    id: "zendesk",
    name: "Zendesk",
    mx: [],
    spfIncludes: ["mail.zendesk.com"],
    dkimSelectors: ["zendesk1", "zendesk2"],
    dkimTargets: ["zendesk.com"],
    sendOnly: true,
  },
  {
    id: "mandrill",
    name: "Mailchimp Transactional",
    mx: [],
    spfIncludes: [],
    dkimSelectors: ["mte1", "mte2"],
    dkimTargets: ["mandrillapp.com"],
  },
  {
    id: "hostinger",
    name: "Hostinger Email",
    mx: ["mx1.hostinger.com", "mx2.hostinger.com"],
    spfIncludes: ["_spf.mail.hostinger.com"],
    dkimSelectors: ["hostingermail-a", "hostingermail-b", "hostingermail-c"],
    dkimTargets: ["dkim.mail.hostinger.com"],
    rotationGroups: [["hostingermail-a", "hostingermail-b", "hostingermail-c"]],
  },
  {
    id: "ionos",
    name: "IONOS",
    mx: ["ionos.com", "1and1.com", "ionos.de", "kundenserver.de", "ionos.es", "1and1.es", "1and1.fr"],
    // Its US and EU includes each hold for some countries only, and no page maps them all.
    spfIncludes: [],
    dkimSelectors: ["s1-ionos", "s2-ionos"],
    dkimTargets: ["dkim.ionos.com"],
  },
  {
    id: "gandi",
    name: "Gandi Mail",
    mx: ["mail.gandi.net"],
    spfIncludes: ["_mailcust.gandi.net"],
    dkimSelectors: ["gm1", "gm2", "gm3"],
    dkimTargets: ["gandimail.net"],
    rotationGroups: [["gm1", "gm2", "gm3"]],
  },
  {
    id: "migadu",
    name: "Migadu",
    mx: ["migadu.com"],
    spfIncludes: ["spf.migadu.com"],
    dkimSelectors: ["key1", "key2", "key3"],
    dkimTargets: ["migadu.com"],
  },
  {
    id: "namecheap-private-email",
    name: "Namecheap Private Email",
    mx: ["privateemail.com"],
    spfIncludes: ["spf.privateemail.com"],
    dkimSelectors: ["privateemail"],
  },
  {
    id: "purelymail",
    name: "Purelymail",
    mx: ["purelymail.com"],
    spfIncludes: ["_spf.purelymail.com"],
    dkimSelectors: ["purelymail1", "purelymail2", "purelymail3"],
    dkimTargets: ["dkimroot.purelymail.com"],
    rotationGroups: [["purelymail1", "purelymail2", "purelymail3"]],
  },
  {
    id: "mailbox-org",
    name: "mailbox.org",
    mx: ["mailbox.org"],
    spfIncludes: ["mailbox.org"],
    dkimSelectors: ["mbo0001", "mbo0002", "mbo0003", "mbo0004"],
    dkimTargets: ["mailbox.org"],
    rotationGroups: [["mbo0001", "mbo0002", "mbo0003", "mbo0004"]],
  },
  {
    id: "strato",
    name: "Strato",
    mx: ["rzone.de"],
    // Its page gives redirect=_spf.strato.com when it sends alone (spfRedirect), else this include.
    spfIncludes: ["_spf.strato.com"],
    spfRedirect: true,
    dkimSelectors: ["strato-dkim-0002", "strato-dkim-0003"],
    dkimTargets: ["rzone.de"],
    rotationGroups: [["strato-dkim-0002", "strato-dkim-0003"]],
  },
  { id: "mailerlite", name: "MailerLite", mx: [], spfIncludes: [], dkimSelectors: ["litesrv"], dkimTargets: ["mlsend.com"] },
  { id: "help-scout", name: "Help Scout", mx: [], spfIncludes: [], dkimSelectors: ["strong1", "strong2"], dkimTargets: ["helpscout.net"] },
  { id: "constant-contact", name: "Constant Contact", mx: [], spfIncludes: [], dkimSelectors: ["ctct1", "ctct2"], dkimTargets: ["ccsend.com"] },
  { id: "squarespace", name: "Squarespace Email Campaigns", mx: [], spfIncludes: [], dkimSelectors: ["squarespace"], dkimTargets: ["squarespace-mail.com"] },
  // No dkimTargets, as its page names the selectors but not their target; the entry is here for
  // the rotation group (one shared key live, the other emptied).
  { id: "mailpoet", name: "MailPoet", mx: [], spfIncludes: [], dkimSelectors: ["mailpoet1", "mailpoet2"], rotationGroups: [["mailpoet1", "mailpoet2"]] },
  // Its selectors and target name the provider of a key found there.
  { id: "emma", name: "Emma", mx: [], spfIncludes: [], dkimSelectors: ["e2ma-k1", "e2ma-k2", "e2ma-k3"], dkimTargets: ["dkim.e2ma.net"] },
  // The providers from here on, with their sources in more.ts of the sources folder, list no
  // selector: each one's is per customer, generic (mail, default, a1) or not tried, so none is
  // asked about by spf-unused-include; a key under a given selector is theirs by a documented
  // target. Alone, Yandex 360 and VK WorkSpace give redirect= (spfRedirect), like Strato.
  { id: "yandex-360", name: "Yandex 360", mx: ["mx.yandex.net"], spfIncludes: ["_spf.yandex.net"], spfRedirect: true, dkimSelectors: [] },
  { id: "tencent-exmail", name: "Tencent Exmail", mx: ["mxbiz1.qq.com", "mxbiz2.qq.com"], spfIncludes: ["spf.mail.qq.com"], dkimSelectors: [] },
  { id: "alibaba-mail", name: "Alibaba Mail", mx: ["qiye.aliyun.com", "mxhichina.com"], spfIncludes: ["spf.qiye.aliyun.com"], dkimSelectors: [] },
  { id: "ovhcloud", name: "OVHcloud", mx: ["mail.ovh.net"], spfIncludes: ["mx.ovh.com"], dkimSelectors: [], dkimTargets: ["dkim.mail.ovh.net"] },
  // Named by its own MX only: _spf.hostedemail.com is the include of Tucows' hosted email, which
  // resellers sell under their own names, so it names no one; a domain with Hover's MX and no SPF
  // still gets it, as Hover's page gives it.
  { id: "hover", name: "Hover", mx: ["mx.hover.com.cust.hostedemail.com"], spfIncludes: [], fixInclude: "_spf.hostedemail.com", dkimSelectors: [] },
  { id: "vk-workspace", name: "VK WorkSpace", mx: ["emx.mail.ru"], spfIncludes: ["_spf.mail.ru"], spfRedirect: true, dkimSelectors: [] },
  { id: "rackspace", name: "Rackspace Email", mx: ["emailsrvr.com"], spfIncludes: ["emailsrvr.com"], dkimSelectors: [] },
  { id: "salesforce", name: "Salesforce", mx: [], spfIncludes: ["_spf.salesforce.com"], dkimSelectors: [], dkimTargets: ["custdkim.salesforce.com"] },
  { id: "aruba", name: "Aruba", mx: [], spfIncludes: ["_spf.aruba.it"], dkimSelectors: [] },
  // Named by its own MX, as Hover: spf.webapps.net is in the SPF of Amen's customers too, so it
  // names no one; a domain with its MX and no SPF still gets it, as Register.it's page gives it.
  { id: "register-nominalia", name: "Register.it and Nominalia", mx: ["mail.register.it"], spfIncludes: [], fixInclude: "spf.webapps.net", dkimSelectors: [], dkimTargets: ["securemail.pro"] },
  { id: "infomaniak", name: "Infomaniak", mx: ["mta-gw.infomaniak.ch"], spfIncludes: ["spf.infomaniak.ch"], dkimSelectors: [] },
  { id: "locaweb", name: "Locaweb", mx: ["locaweb.com.br"], spfIncludes: ["_spf.locaweb.com.br"], dkimSelectors: [] },
  { id: "transip", name: "TransIP", mx: ["mx.transip.email"], spfIncludes: ["_spf.transip.email"], dkimSelectors: [], dkimTargets: ["transip.email"] },
  { id: "netcup", name: "netcup", mx: [], spfIncludes: ["_spf.webhosting.systems"], dkimSelectors: [], dkimTargets: ["webhosting.systems"] },
  // Its include covers only its own relay; the customer's server is the MX host, which a and mx
  // authorize, so the fix writes the page's whole record. Mijndomein's page too.
  { id: "all-inkl", name: "ALL-INKL.COM", mx: ["kasserver.com"], spfIncludes: ["spf.kasserver.com"], fixMechanisms: ["a", "mx"], dkimSelectors: [] },
  { id: "cyber-folks", name: "cyber_Folks", mx: [], spfIncludes: ["_spf.cyberfolks.pl"], dkimSelectors: [] },
  { id: "godaddy", name: "GoDaddy", mx: ["smtp.secureserver.net", "mailstore1.secureserver.net"], spfIncludes: ["secureserver.net"], dkimSelectors: [] },
  { id: "arsys", name: "Arsys", mx: [], spfIncludes: ["_spf.serviciodecorreo.es"], dkimSelectors: [] },
  { id: "hostnet", name: "Hostnet", mx: [], spfIncludes: ["_spf.hostnet.nl"], dkimSelectors: [] },
  { id: "antagonist", name: "Antagonist", mx: [], spfIncludes: ["_spf.webhostingserver.nl"], dkimSelectors: [], dkimTargets: ["dkim.webhostingserver.nl"] },
  // Its own entry, not Namecheap Private Email's: forwarding only receives, and a forwarding-only
  // domain would otherwise be asked whether Private Email still sends (privateemail is that one's).
  { id: "namecheap-email-forwarding", name: "Namecheap Email Forwarding", mx: [], spfIncludes: ["spf.efwd.registrar-servers.com"], dkimSelectors: [], receiveOnly: true },
  // A security gateway's MX says it filters incoming mail, not that the domain sends through it,
  // so none of it is a sending MX (sendingMx empty) and spf-missing never writes its include. Its
  // own include in the SPF does say the domain sends through it, so sendingServices counts it
  // then. Mimecast's regional includes sit under _netblocks.mimecast.com.
  { id: "mimecast", name: "Mimecast", mx: ["mimecast.com", "mimecast.co.za", "mimecast-offshore.com"], sendingMx: [], spfIncludes: ["_netblocks.mimecast.com"], dkimSelectors: [] },
  // Its accounts in Germany, the UK and Australia have their MX under a regional name.
  {
    id: "barracuda",
    name: "Barracuda Email Gateway Defense",
    mx: ["ess.barracudanetworks.com", "ess.de.barracudanetworks.com", "ess.uk.barracudanetworks.com", "ess.au.barracudanetworks.com"],
    sendingMx: [],
    spfIncludes: ["spf.ess.barracudanetworks.com", "spf.ess.au.barracudanetworks.com", "spf.ess.ca.barracudanetworks.com", "spf.ess.de.barracudanetworks.com", "spf.ess.in.barracudanetworks.com", "spf.ess.uk.barracudanetworks.com"],
    dkimSelectors: [],
  },
  { id: "hornetsecurity", name: "Hornetsecurity", mx: ["hornetsecurity.com"], sendingMx: [], spfIncludes: ["spf.hornetsecurity.com"], dkimSelectors: [] },
  { id: "cisco-secure-email", name: "Cisco Secure Email", mx: ["iphmx.com"], sendingMx: [], spfIncludes: [], dkimSelectors: [] },
  { id: "marketo", name: "Adobe Marketo Engage", mx: [], spfIncludes: ["mktomail.com"], dkimSelectors: [] },
  { id: "elastic-email", name: "Elastic Email", mx: [], spfIncludes: ["_spf.elasticemail.com"], dkimSelectors: [] },
  { id: "mailchannels", name: "MailChannels", mx: [], spfIncludes: ["relay.mailchannels.net"], dkimSelectors: [] },
  { id: "activecampaign", name: "ActiveCampaign", mx: [], spfIncludes: ["emsd1.com"], dkimSelectors: [] },
  // websitewelcome.com is the include of HostGator in the US and of Bluehost too, so it names no
  // one (SHARED_INCLUDES); with no MX of its own either, the entry recognizes nothing and only
  // documents the provider.
  { id: "hostgator-brasil", name: "HostGator Brasil", mx: [], spfIncludes: [], dkimSelectors: [] },
  { id: "hetzner", name: "Hetzner", mx: ["your-server.de"], spfIncludes: [], dkimSelectors: [] },
  { id: "host-europe", name: "Host Europe", mx: [], spfIncludes: ["spf.server-he.de"], dkimSelectors: [] },
  { id: "o2switch", name: "o2switch", mx: [], spfIncludes: ["spf.jabatus.fr"], dkimSelectors: [] },
  { id: "kinghost", name: "KingHost", mx: [], spfIncludes: ["_spf.kinghost.net", "_spf.uni5.net"], dkimSelectors: [] },
  { id: "mijndomein", name: "Mijndomein", mx: ["mx1.mijndomein.nl", "mx2.mijndomein.nl"], spfIncludes: ["spf.mijndomeinhosting.nl"], fixMechanisms: ["a", "mx"], dkimSelectors: [] },
];

/**
 * The selectors tried on every check, in a fixed order so the queries and the tests are
 * reproducible: the selectors of the providers here, of other common sending services, and the
 * defaults of common mail servers.
 */
export const SELECTORS: readonly string[] = (
  "google selector1 selector2 fm1 fm2 fm3 protonmail protonmail2 protonmail3 sig1 cf2024-1 zoho s1 s2 k1 k2 k3 resend brevo1 brevo2 mail " +
  "smtp mx pic default dkim mandrill kl kl2 zendesk1 zendesk2 mailjet mte1 mte2 intercom cm krs mailo x hostingermail-a hostingermail-b " +
  "hostingermail-c s1-ionos s2-ionos litesrv acdkim1 strong1 strong2 ctct1 ctct2 key1 key2 key3 m1 squarespace gm1 gm2 gm3 kl1 privateemail " +
  "purelymail1 purelymail2 purelymail3 mbo0001 mbo0002 mbo0003 mbo0004 strato-dkim-0002 strato-dkim-0003 cf-bounce a1 mailpoet1 mailpoet2 " +
  "e2ma-k1 e2ma-k2 e2ma-k3"
).split(" ");

/**
 * Selectors in a provider's list that other services and self-hosted servers also use: tried, and
 * counted as the provider's own by spf-unused-include, but attributed only through a documented
 * CNAME target, never by the name. Mailgun documents no target for them (sources folder), so a key
 * there is no one's.
 */
const GENERIC_SELECTORS: ReadonlySet<string> = new Set(["smtp", "mx"]);

/**
 * SPF includes several hosts give, so they name no one, and what they include is the host's, not
 * the domain's: websitewelcome.com (HostGator in the US, Bluehost and HostGator Brasil) includes
 * Google's and Microsoft's, and each fixInclude (Hover's Tucows include, Register.it's
 * spf.webapps.net) is one too.
 */
export const SHARED_INCLUDES: readonly string[] = [
  "websitewelcome.com",
  ...providerList.flatMap((p) => (p.fixInclude ? [p.fixInclude] : [])),
];

/** Whether a live key's CNAME chain reaches one of the provider's documented targets. */
export function reachesTarget(p: Provider, chain: readonly string[]): boolean {
  return (p.dkimTargets ?? []).some((t) => chain.some((n) => isAtOrBelow(n, t)));
}

export function providersForMx(host: string): Readonly<Provider>[] {
  return providerList.filter((p) => p.mx.some((m) => isAtOrBelow(host, m)));
}

/** The providers an MX host says the domain sends through: their sendingMx, or all their mx. */
export function sendersForMx(host: string): Readonly<Provider>[] {
  return providerList.filter((p) => (p.sendingMx ?? p.mx).some((m) => isAtOrBelow(host, m)));
}

export function providersForInclude(domain: string): Readonly<Provider>[] {
  return providerList.filter((p) => p.spfIncludes.some((i) => isAtOrBelow(domain, i)));
}

/**
 * The provider a live key belongs to: by the CNAME chain first, the longest dkimTargets suffix
 * that some name of the chain sits under; else by the selector's name, only for the one provider
 * that uses it and has no dkimTargets, since a provider with them publishes its keys by CNAME.
 * default, dkim and x are the defaults of cPanel, rspamd and DirectAdmin, and mail is Brevo's and
 * Yandex 360's: none of them is in a provider's list. smtp and mx are in Mailgun's, but generic
 * (GENERIC_SELECTORS).
 * A selector tried on every check counts by its target only when the chain reaches the target of
 * a provider whose list holds that selector (then the longest suffix still decides, so Klaviyo's
 * SendGrid account keeps s1): a customer's own name that happens to be one of them (selector1, s1,
 * key1, default) into another's target says nothing, and a question about it would push to delete
 * a key in use.
 */
export function ownerOf(selector: string, chain: readonly string[]): Readonly<Provider> | undefined {
  const gated =
    SELECTORS.includes(selector) &&
    !providerList.some((p) => p.dkimSelectors.includes(selector) && reachesTarget(p, chain));
  let best: Readonly<Provider> | undefined;
  let length = 0;
  for (const p of gated ? [] : providerList) {
    for (const t of p.dkimTargets ?? [])
      if (t.length > length && chain.some((n) => isAtOrBelow(n, t))) {
        best = p;
        length = t.length;
      }
  }
  if (best) return best;
  if (GENERIC_SELECTORS.has(selector)) return undefined;
  const named = providerList.filter((p) => p.dkimSelectors.includes(selector));
  return named.length === 1 && !named[0]?.dkimTargets ? named[0] : undefined;
}

/** The rotation group a selector belongs to, if any (Microsoft 365: selector1 and selector2). */
export function rotationGroupOf(selector: string): readonly string[] | undefined {
  for (const p of providerList) for (const g of p.rotationGroups ?? []) if (g.includes(selector)) return g;
  return undefined;
}

/**
 * The services that send email as the domain, among those the check found (report.providers):
 * every one but those that only receive and forward, and those seen only by an MX that says
 * nothing of sending (report.inboundOnly: a gateway, an SES receiving endpoint).
 */
export function sendingServices(report: Pick<Report, "providers" | "inboundOnly">): Readonly<Provider>[] {
  return report.providers.flatMap((id) =>
    report.inboundOnly?.includes(id) ? [] : (providerList.find((p) => p.id === id && !p.receiveOnly) ?? []),
  );
}
