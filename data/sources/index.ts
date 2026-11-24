// Where each value of providers.ts comes from, one entry per value: the vendor page that says it,
// with its quote and the day it was read, or the domains it was seen on in DNS. Every vendor page
// here was read on its `read` date, and each quote was checked against that day's text. The engine
// never imports this folder; the tests do, and the provider dataset is built from it.
// Each link sits in a string of its page constant, never in a comment, so a script can collect
// every link of this file and of more.ts, whose entries this one takes in.
// “The sample” below is a measurement of 2,707 domains made on 2026-11-19, not published.
import { SELECTORS } from "../../src/providers.ts";
import { ACTIVECAMPAIGN, ARUBA, moreEmptyFields, moreFlags, moreValues } from "./more.ts";
import { dns, empty, none, page, READ_2026_11_20, TXT_KEY, unused, value, vendor } from "./builders.ts";

/**
 * vendor: the vendor's own page says it; dns: seen in DNS on seenOn; measured: measured for this
 * data.
 */
export type Basis = "vendor" | "dns" | "measured";
export type ProviderField = "mx" | "spfIncludes" | "dkimSelectors" | "dkimTargets";

export interface Backing {
  basis: Basis;
  /** The page read, for vendor. */
  url?: string;
  /** The day the page was read or the value seen in DNS. */
  read: string;
  /** The vendor's words behind the value, for vendor. */
  quote?: string;
  /** The domains where it was seen, for dns. */
  seenOn?: string[];
}

export interface ValueSource extends Backing {
  /** An id of providers.ts. */
  provider: string;
  field: ProviderField;
  value: string;
}

/**
 * Why a provider's list is empty. none-documented: the page read gives no such value;
 * documented-not-used: it gives one the engine does not use, the note says why, and `documented`
 * and `quote` hold that value and the vendor's words that give it;
 * not-read: no page was read for it.
 */
export interface EmptyField {
  provider: string;
  field: ProviderField;
  reason: "none-documented" | "documented-not-used" | "not-read";
  note?: string;
  url?: string;
  read?: string;
  documented?: string;
  quote?: string;
}

export interface SelectorSource extends Backing {
  selector: string;
  /** Who uses a selector that is in no provider's list, as its source says. */
  usedBy?: string;
}

/**
 * The vendor's words behind a flag of the engine, which the provider dataset does not publish:
 * sendOnly, receiveOnly, spfRedirect, the redirect= the vendor gives for a domain where it sends
 * alone, and fixMechanisms, the mechanisms its record writes before its include.
 */
export interface FlagSource {
  provider: string;
  flag: "sendOnly" | "receiveOnly" | "spfRedirect" | "fixMechanisms";
  url: string;
  read: string;
  quote: string;
}

// The pages, one constant each, so a reread changes one date.
const GOOGLE_DKIM = page("https://knowledge.workspace.google.com/admin/security/set-up-dkim", READ_2026_11_20);
const GOOGLE_MX = page("https://knowledge.workspace.google.com/admin/domains/set-up-mx-records-for-google-workspace", READ_2026_11_20);
const GOOGLE_SPF = page("https://knowledge.workspace.google.com/admin/security/set-up-spf", READ_2026_11_20);
const MS_DKIM = page("https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure", READ_2026_11_20);
const MS_DNS = page("https://learn.microsoft.com/en-us/microsoft-365/enterprise/external-domain-name-system-records", READ_2026_11_20);
const MS_DANE = page("https://learn.microsoft.com/en-us/exchange/security-and-compliance/how-dane-secures-email", READ_2026_11_20);
const FASTMAIL = page("https://www.fastmail.help/hc/en-us/articles/360060591153-Manual-DNS-configuration", READ_2026_11_20);
const ZOHO_DKIM = page("https://www.zoho.com/mail/help/adminconsole/dkim-configuration.html", READ_2026_11_20);
const ZOHO_MX = page("https://www.zoho.com/mail/help/adminconsole/configure-email-delivery.html", READ_2026_11_20);
const ZOHO_SPF = page("https://www.zoho.com/mail/help/adminconsole/spf-configuration.html", READ_2026_11_20);
const PROTON_SPOOFING = page("https://proton.me/support/anti-spoofing-custom-domain", READ_2026_11_20);
const PROTON_CLOUDFLARE = page("https://proton.me/support/custom-domain-cloudflare", READ_2026_11_20);
const APPLE = page("https://support.apple.com/en-us/102374", READ_2026_11_20);
const CLOUDFLARE = page("https://developers.cloudflare.com/email-service/configuration/domains/", READ_2026_11_20);
const SES_MAIL_FROM = page("https://docs.aws.amazon.com/ses/latest/dg/mail-from.html", READ_2026_11_20);
// The HTML page, not its Markdown copy; quoted as the HTML shows it, read 2026-11-20.
const SES_IDENTITIES = page("https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html", READ_2026_11_20);
const SENDGRID = page("https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication", READ_2026_11_20);
// The Mailgun and Brevo help centers answer 403 to scripts; they were read through the public
// Help Center API (/api/v2/help_center/en-us/articles/<id>.json), which serves the same article.
const MAILGUN_CLOUDFLARE = page("https://help.mailgun.com/hc/en-us/articles/15585722150299-Cloudflare-DNS-Setup-Guide", READ_2026_11_20);
const MAILGUN_VERIFICATION = page("https://help.mailgun.com/hc/en-us/articles/32884700912923-Domain-Verification-Setup-Guide", READ_2026_11_20);
const MAILGUN_ROTATE = page("https://help.mailgun.com/hc/en-us/articles/16956951504539-How-can-I-rotate-my-DKIM-key", READ_2026_11_20);
const MAILGUN_FAQ = page("https://help.mailgun.com/hc/en-us/articles/360011565514-DNS-frequently-asked-questions", READ_2026_11_20);
const POSTMARK_DKIM = page("https://postmarkapp.com/support/article/1091-how-do-i-set-up-dkim-for-postmark", READ_2026_11_20);
const POSTMARK_RETURN_PATH = page("https://postmarkapp.com/support/article/910-how-do-i-add-a-custom-return-path", READ_2026_11_20);
const RESEND = page("https://resend.com/docs/llms-full.txt", READ_2026_11_20);
const BREVO = page("https://help.brevo.com/hc/en-us/articles/16045394674066", READ_2026_11_20);
const BREVO_API = page("https://developers.brevo.com/reference/create-domain", READ_2026_11_20);
const MAILCHIMP = page("https://mailchimp.com/help/set-up-email-domain-authentication/", READ_2026_11_20);
const KLAVIYO_SETUP = page("https://help.klaviyo.com/hc/en-us/articles/115000357752", READ_2026_11_20);
const KLAVIYO_TROUBLESHOOTING = page("https://help.klaviyo.com/hc/en-us/articles/4417768780827", READ_2026_11_20);
const ZENDESK_DKIM = page("https://support.zendesk.com/hc/en-us/articles/4408822303386-Digitally-signing-your-email-with-DKIM", READ_2026_11_20);
const ZENDESK_SPF = page("https://support.zendesk.com/hc/en-us/articles/4408832543770-Allowing-Zendesk-to-send-email-on-behalf-of-your-email-domain", READ_2026_11_20);
const MANDRILL = page("https://mailchimp.com/developer/transactional/docs/authentication-delivery/", READ_2026_11_20);
const HOSTINGER_DKIM = page("https://www.hostinger.com/support/4456413-what-are-the-dkim-records-for-hostinger-email/", READ_2026_11_20);
const HOSTINGER_MX = page("https://www.hostinger.com/support/4407237-hostinger-email-mx-records/", READ_2026_11_20);
const HOSTINGER_SPF = page("https://www.hostinger.com/support/1583673-what-is-the-spf-record-for-hostinger-email/", READ_2026_11_20);
const IONOS_DKIM = page("https://www.ionos.com/help/domains/configuring-mail-servers-and-other-related-records/email-authentication-with-dkim", READ_2026_11_20);
const IONOS_MX = page("https://www.ionos.com/help/email/troubleshooting-mail-basic-mail-business/adjusting-mx-records-for-receiving-email-via-ionos-mail-servers/", READ_2026_11_20);
const IONOS_MX_DE = page("https://www.ionos.de/hilfe/e-mail/problemloesungen-mail-basicmail-business/mx-eintraege-fuer-e-mail-empfang-ueber-ionos-mailserver-anpassen/", READ_2026_11_20);
const IONOS_SPF = page("https://www.ionos.com/help/domains/configuring-mail-servers-and-other-related-records/using-ionos-spf-to-improve-email-delivery/", READ_2026_11_20);
const GANDI = page("https://docs.gandi.net/en/gandimail/common_operations/enable_antispoofing_tools.html", READ_2026_11_20);
const GANDI_MX = page("https://docs.gandi.net/en/domain_names/faq/record_types/mx_record.html", READ_2026_11_20);
// The API reference is the only public page with the records; the DNS guides answer 404.
const MIGADU = page("https://www.migadu.com/api/", READ_2026_11_20);
const NAMECHEAP = page("https://www.namecheap.com/support/knowledgebase/article.aspx/1340/2176/namecheap-private-email-records-for-domains-with-thirdparty-dns/", READ_2026_11_20);
const NAMECHEAP_DKIM = page("https://www.namecheap.com/support/knowledgebase/article.aspx/10383/2176/how-to-set-up-a-dkim-record-for-private-email/", READ_2026_11_20);
const PURELYMAIL = page("https://purelymail.com/docs/domainDocs", READ_2026_11_20);
const MAILBOX = page("https://kb.mailbox.org/en/private/custom-domains/spf-dkim-and-dmarc/", READ_2026_11_20);
const MAILBOX_MX = page("https://kb.mailbox.org/en/private/custom-domains/using-emails-with-a-custom-domain/", READ_2026_11_20);
const STRATO = page("https://www.strato.de/faq/domains/wie-kann-ich-bei-strato-meine-dns-eintraege-verwalten/", READ_2026_11_20);
const MAILERLITE = page("https://www.mailerlite.com/help/how-to-authenticate-a-domain-with-cloudflare", READ_2026_11_20);
const HELPSCOUT = page("https://docs.helpscout.com/article/666-use-dkim-to-help-with-email-delivery", READ_2026_11_20);
const HELPSCOUT_SPF = page("https://docs.helpscout.com/article/58-spf-records", READ_2026_11_20);
// The Constant Contact, Campaign Monitor and Emma pages render their text with JavaScript; they
// were read with headless Chromium.
const CTCT = page("https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/39520-Update-your-DNS-records-through-your-hosting-provider-to-finish-setting-up-self-authentication?lang=en_US", READ_2026_11_20);
const CTCT_TROUBLESHOOTING = page("https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/49735-Troubleshooting-DKIM-self-authentication-using-CNAME-TXT-and-DMARC?lang=en_US", READ_2026_11_20);
const SQUARESPACE = page("https://support.squarespace.com/hc/en-us/articles/360001280748-Verify-your-third-party-domain-for-use-with-Email-Campaigns", READ_2026_11_20);
const MAILPOET = page("https://kb.mailpoet.com/article/295-spf-dkim-dmarc", READ_2026_11_20);
const EMMA = page("https://help.myemma.com/s/article/DomainKeys-Identified-Mail-DKIM", READ_2026_11_20);
const CPANEL = page("https://support.cpanel.net/hc/en-us/articles/4402780648983-Does-cPanel-support-custom-DKIM-selectors", READ_2026_11_20);
const RSPAMD = page("https://docs.rspamd.com/modules/dkim_signing/", READ_2026_11_20);
const MAILJET = page("https://dev.mailjet.com/docs/email-api/senders-domains/spf-dkim-validation", READ_2026_11_20);
const INTERCOM = page("https://www.intercom.com/help/en/articles/11183745-troubleshooting-email-authentication-issues-dkim-dmarc-and-dns-setup", READ_2026_11_20);
const CAMPAIGN_MONITOR = page("https://help.campaignmonitor.com/s/article/use-your-own-domains", READ_2026_11_20);
const DIRECTADMIN = page("https://docs.directadmin.com/directadmin/general-usage/all-directadmin-conf-values.html", READ_2026_11_20);

/** One entry per value of providerList, in its order. */
export const valueSources: readonly ValueSource[] = [
  value("google-workspace", "mx", "smtp.google.com", vendor(GOOGLE_MX, "The Google Workspace MX record value is smtp.google.com .")),
  // The page gives only the prefix of the legacy values (“start with "aspmx"”), so the value is the
  // one seen in DNS, by DoH on 2026-11-20.
  value("google-workspace", "mx", "aspmx.l.google.com", dns(READ_2026_11_20, "zapier.com", "stripe.com", "airbnb.com", "shopify.com")),
  value("google-workspace", "spfIncludes", "_spf.google.com", vendor(GOOGLE_SPF, "If you use only Google Workspace to send email, copy this line of text: v=spf1 include:_spf.google.com ~all")),
  value("google-workspace", "dkimSelectors", "google", vendor(GOOGLE_DKIM, "The default prefix selector is google .")),

  value("microsoft-365", "mx", "mail.protection.outlook.com", vendor(MS_DNS, "Target email server: <MX token>.mail.protection.outlook.com")),
  value("microsoft-365", "mx", "mx.microsoft", vendor(MS_DANE, "This value is the name that the new MX record points to for the domain you're enabling with DNSSEC. For example, contosotest-com.o-v1.mx.microsoft .")),
  value("microsoft-365", "spfIncludes", "spf.protection.outlook.com", vendor(MS_DNS, "TXT Name @ Values: v=spf1 include:spf.protection.outlook.com -all")),
  value("microsoft-365", "dkimSelectors", "selector1", vendor(MS_DKIM, "Points to address or value: selector1-contoso-com._domainkey.contoso.onmicrosoft.com")),
  value("microsoft-365", "dkimSelectors", "selector2", vendor(MS_DKIM, "Hostname: selector2._domainkey")),
  value("microsoft-365", "dkimTargets", "onmicrosoft.com", vendor(MS_DKIM, "Points to address or value: selector1-contoso-com._domainkey.contoso.onmicrosoft.com")),
  value("microsoft-365", "dkimTargets", "dkim.mail.microsoft", vendor(MS_DKIM, "dkim.mail.microsoft : The parent DNS zone that's the same for both selectors.")),
  // GCC High tenants point to onmicrosoft.us (navy.mil in the sample), which these
  // pages do not name: such a key belongs to no provider.

  value("fastmail", "mx", "messagingengine.com", vendor(FASTMAIL, "MX @ in1-smtp.messagingengine.com 10")),
  value("fastmail", "spfIncludes", "spf.messagingengine.com", vendor(FASTMAIL, "TXT {mydomain.com} v=spf1 include:spf.messagingengine.com ?all")),
  value("fastmail", "dkimSelectors", "fm1", vendor(FASTMAIL, "CNAME fm1._domainkey fm1.{mydomain.com}.dkim.fmhosted.com")),
  value("fastmail", "dkimSelectors", "fm2", vendor(FASTMAIL, "CNAME fm2._domainkey fm2.{mydomain.com}.dkim.fmhosted.com")),
  value("fastmail", "dkimSelectors", "fm3", vendor(FASTMAIL, "CNAME fm3._domainkey fm3.{mydomain.com}.dkim.fmhosted.com")),
  value("fastmail", "dkimTargets", "dkim.fmhosted.com", vendor(FASTMAIL, "CNAME fm1._domainkey fm1.{mydomain.com}.dkim.fmhosted.com")),
  // 18 of 32 Fastmail-named keys in the sample point to fmN-<id>-<domain>.fmdkim.net,
  // which the page does not name: those keys belong to no provider.

  value("zoho-mail", "mx", "zoho.com", vendor(ZOHO_MX, "@/ Blank/ Domain name mx.zoho.com 10")),
  // The page gives mx.zoho.*** with the TLD of the data center, and zoho.eu redirects to it, so the
  // value is the one seen in DNS, by DoH on 2026-11-20.
  value("zoho-mail", "mx", "zoho.eu", dns(READ_2026_11_20, "zoho.eu")),
  value("zoho-mail", "spfIncludes", "zohomail.com", vendor(ZOHO_SPF, "The Valid SPF records that need to be published are provided below: v=spf1 include:zohomail.com -all")),
  value("zoho-mail", "spfIncludes", "one.zoho.com", vendor(ZOHO_SPF, "In case you are using multiple Zoho services, you can use v=spf1 include:one.zoho.com -all to avoid any SPF lookup failure.")),
  value("zoho-mail", "dkimSelectors", "zoho", vendor(ZOHO_DKIM, "zoho._domainkey")),

  value("proton-mail", "mx", "protonmail.ch", vendor(PROTON_CLOUDFLARE, "Mail server : mail.protonmail.ch")),
  value("proton-mail", "spfIncludes", "_spf.protonmail.ch", vendor(PROTON_SPOOFING, "The “include:_spf.protonmail.ch” part of the text string means that you allow Proton Mail servers to send on behalf of your domain.")),
  value("proton-mail", "dkimSelectors", "protonmail", vendor(PROTON_CLOUDFLARE, "Name : protonmail._domainkey")),
  value("proton-mail", "dkimSelectors", "protonmail2", vendor(PROTON_CLOUDFLARE, "To add a second and third DKIM record, repeat these steps with the appropriate record names protonmail2._domainkey and protonmail3._domainkey .")),
  value("proton-mail", "dkimSelectors", "protonmail3", vendor(PROTON_CLOUDFLARE, "To add a second and third DKIM record, repeat these steps with the appropriate record names protonmail2._domainkey and protonmail3._domainkey .")),

  value("icloud", "mx", "mail.icloud.com", vendor(APPLE, "Record Type: MX Host: @ Value: mx01.mail.icloud.com.")),
  value("icloud", "spfIncludes", "icloud.com", vendor(APPLE, 'Record Type: TXT Host: @ Value: "v=spf1 include:icloud.com ~all"')),
  value("icloud", "dkimSelectors", "sig1", vendor(APPLE, "Record Type: CNAME Host: sig1._domainkey Value: sig1.dkim.example.com.at.icloudmailadmin.com.")),
  value("icloud", "dkimTargets", "at.icloudmailadmin.com", vendor(APPLE, "Record Type: CNAME Host: sig1._domainkey Value: sig1.dkim.example.com.at.icloudmailadmin.com.")),

  value("cloudflare-email-routing", "mx", "mx.cloudflare.net", vendor(CLOUDFLARE, "Purpose : Route incoming emails to Cloudflare's mail servers. MX yourdomain.com route1.mx.cloudflare.net")),
  value("cloudflare-email-routing", "spfIncludes", "_spf.mx.cloudflare.net", vendor(CLOUDFLARE, "v=spf1 include:_spf.mx.cloudflare.net ~all")),
  value("cloudflare-email-routing", "dkimSelectors", "cf2024-1", vendor(CLOUDFLARE, "TXT cf2024-1._domainkey.yourdomain.com")),

  value("amazon-ses", "mx", "amazonses.com", vendor(SES_MAIL_FROM, "subdomain.domain.com MX 10 feedback-smtp.region.amazonses.com")),
  value("amazon-ses", "spfIncludes", "amazonses.com", vendor(SES_MAIL_FROM, 'subdomain.domain.com TXT "v=spf1 include:amazonses.com ~all"')),
  value("amazon-ses", "dkimTargets", "amazonses.com", vendor(SES_IDENTITIES, "Each CNAME record's value is composed of the DKIM token followed by a hosted zone domain (for example, token.dkim.us-west-2.amazonses.com). The hosted zone portion varies by AWS Region and identity.")),

  value("sendgrid", "mx", "sendgrid.net", vendor(SENDGRID, "MX em[0000].example.com mx.sendgrid.net. MX")),
  value("sendgrid", "spfIncludes", "sendgrid.net", vendor(SENDGRID, "TXT em[0000].example.com v=spf1 include:sendgrid.net ~all SPF")),
  value("sendgrid", "dkimSelectors", "s1", vendor(SENDGRID, "s1._domainkey.example.com s1.domainkey.[u00000000].[wl000].sendgrid.net DKIM")),
  value("sendgrid", "dkimSelectors", "s2", vendor(SENDGRID, "s2._domainkey.example.com s2.domainkey.[u00000000].[wl000].sendgrid.net DKIM")),
  value("sendgrid", "dkimSelectors", "m1", vendor(SENDGRID, "m1._domainkey.example.com k=rsa; t=s; p=MIG... DKIM")),
  value("sendgrid", "dkimTargets", "sendgrid.net", vendor(SENDGRID, "s1._domainkey.example.com s1.domainkey.[u00000000].[wl000].sendgrid.net DKIM")),

  value("mailgun", "mx", "mailgun.org", vendor(MAILGUN_CLOUDFLARE, "Mail server mxa.mailgun.org (for the first MX record) mxb.mailgun.org (for the second MX record)")),
  value("mailgun", "spfIncludes", "mailgun.org", vendor(MAILGUN_CLOUDFLARE, "Content v=spf1 include:mailgun.org ~all")),
  // smtp and mx are generic (providers.ts, GENERIC_SELECTORS): tried and counted as Mailgun's by
  // spf-unused-include, but a key under them is never Mailgun's by the name alone.
  value("mailgun", "dkimSelectors", "smtp", vendor(MAILGUN_CLOUDFLARE, "pic._domainkey (or, one of several other values such as krs._domainkey , smtp._domainkey , or mailo._domainkey )")),
  value("mailgun", "dkimSelectors", "mx", vendor(MAILGUN_VERIFICATION, "Add another TXT record for mx._domainkey.mail.yourdomain.com .")),
  value("mailgun", "dkimSelectors", "pic", vendor(MAILGUN_CLOUDFLARE, "pic._domainkey (or, one of several other values such as krs._domainkey , smtp._domainkey , or mailo._domainkey )")),
  value("mailgun", "dkimSelectors", "krs", vendor(MAILGUN_CLOUDFLARE, "pic._domainkey (or, one of several other values such as krs._domainkey , smtp._domainkey , or mailo._domainkey )")),
  value("mailgun", "dkimSelectors", "mailo", vendor(MAILGUN_CLOUDFLARE, "pic._domainkey (or, one of several other values such as krs._domainkey , smtp._domainkey , or mailo._domainkey )")),

  value("resend", "dkimSelectors", "resend", vendor(RESEND, "Type `resend._domainkey` for the `Name` of the record.")),

  value("brevo", "dkimSelectors", "brevo1", vendor(BREVO, "DKIM 1 record brevo1._domainkey brevo1._domainkey.yourdomain.com")),
  value("brevo", "dkimSelectors", "brevo2", vendor(BREVO, "DKIM 2 record brevo2._domainkey brevo2._domainkey.yourdomain.com")),

  // The page shows “CNAME 1 and CNAME 2” and names k2 only; k1 and k3 are seen on these two
  // domains, CNAME to dkim.mcsv.net and dkim3.mcsv.net (Cloudflare DoH, 2026-11-20), and 642 keys
  // at k1, k2 and k3 in the sample point under mcsv.net.
  value("mailchimp", "dkimSelectors", "k1", dns(READ_2026_11_20, "mailchimp.com", "intuit.com")),
  value("mailchimp", "dkimSelectors", "k2", vendor(MAILCHIMP, "For example, if you enter “k2._domainkey.example.com” and “k2._domainkey.example.com.example.com” is created")),
  value("mailchimp", "dkimSelectors", "k3", dns(READ_2026_11_20, "mailchimp.com", "intuit.com")),
  value("mailchimp", "dkimTargets", "mcsv.net", dns(READ_2026_11_20, "mailchimp.com", "intuit.com")),

  value("klaviyo", "dkimSelectors", "kl", vendor(KLAVIYO_TROUBLESHOOTING, "Existing static domains can use legacy selector pairs such as kl/kl2 or kl1/kl2 .")),
  value("klaviyo", "dkimSelectors", "kl2", vendor(KLAVIYO_TROUBLESHOOTING, "Existing static domains can use legacy selector pairs such as kl/kl2 or kl1/kl2 .")),
  value("klaviyo", "dkimSelectors", "kl1", vendor(KLAVIYO_SETUP, "your DNS records use the legacy kl1 / kl2 DKIM selectors and continue to work without changes.")),
  // The legacy selectors point into one SendGrid account: kl in 38 of 38 domains and kl2 in 39 of
  // 44 of the sample (the other 5 to klaviyodns.com).
  value("klaviyo", "dkimTargets", "u161779.wl030.sendgrid.net", vendor(KLAVIYO_TROUBLESHOOTING, "this would make the value u161779.wl030.sendgrid.net.rootdomain.com instead of just u161779.wl030.sendgrid.net.")),
  value("klaviyo", "dkimTargets", "klaviyodns.com", vendor(KLAVIYO_SETUP, "km1._domainkey.helloworld.com km1._domainkey.1.klaviyodns.com CNAME")),

  value("zendesk", "spfIncludes", "mail.zendesk.com", vendor(ZENDESK_SPF, "Zendesk recommends using the following SPF record: v=spf1 include:mail.zendesk.com -all")),
  value("zendesk", "dkimSelectors", "zendesk1", vendor(ZENDESK_DKIM, "In the Host Record field (or equivalent), enter: zendesk1._domainkey. your_email_domain.com")),
  value("zendesk", "dkimSelectors", "zendesk2", vendor(ZENDESK_DKIM, "In the Host Record field, enter: zendesk2._domainkey. your_email_domain .com")),
  value("zendesk", "dkimTargets", "zendesk.com", vendor(ZENDESK_DKIM, "In the Points To field (or equivalent), enter: zendesk1._domainkey.zendesk.com")),

  value("mandrill", "dkimSelectors", "mte1", vendor(MANDRILL, "Add two new CNAME records with the names mte1._domainkey.example.com and mte2._domainkey.example.com")),
  value("mandrill", "dkimSelectors", "mte2", vendor(MANDRILL, "Add two new CNAME records with the names mte1._domainkey.example.com and mte2._domainkey.example.com")),
  value("mandrill", "dkimTargets", "mandrillapp.com", vendor(MANDRILL, "The value for the record should first CNAME should be dkim1.mandrillapp.com , and the value for the second record should be dkim2.mandrillapp.com .")),

  value("hostinger", "mx", "mx1.hostinger.com", vendor(HOSTINGER_MX, "@ 5 mx1.hostinger.com")),
  value("hostinger", "mx", "mx2.hostinger.com", vendor(HOSTINGER_MX, "@ 10 mx2.hostinger.com")),
  value("hostinger", "spfIncludes", "_spf.mail.hostinger.com", vendor(HOSTINGER_SPF, "TXT @ v=spf1 include:_spf.mail.hostinger.com ~all")),
  value("hostinger", "dkimSelectors", "hostingermail-a", vendor(HOSTINGER_DKIM, "CNAME hostingermail-a._domainkey hostingermail-a.dkim.mail.hostinger.com")),
  value("hostinger", "dkimSelectors", "hostingermail-b", vendor(HOSTINGER_DKIM, "CNAME hostingermail-b._domainkey hostingermail-b.dkim.mail.hostinger.com")),
  value("hostinger", "dkimSelectors", "hostingermail-c", vendor(HOSTINGER_DKIM, "CNAME hostingermail-c._domainkey hostingermail-c.dkim.mail.hostinger.com")),
  value("hostinger", "dkimTargets", "dkim.mail.hostinger.com", vendor(HOSTINGER_DKIM, "CNAME hostingermail-a._domainkey hostingermail-a.dkim.mail.hostinger.com")),

  value("ionos", "mx", "ionos.com", vendor(IONOS_MX, "receiving emails will only be possible using the correct MX record entries mx00.ionos.com / mx01.ionos.com (alternatively mx00.1and1.com / mx01.1and1.com).")),
  value("ionos", "mx", "1and1.com", vendor(IONOS_MX, "receiving emails will only be possible using the correct MX record entries mx00.ionos.com / mx01.ionos.com (alternatively mx00.1and1.com / mx01.1and1.com).")),
  value("ionos", "mx", "ionos.de", vendor(IONOS_MX_DE, "mx00.ionos.de / mx01.ionos.de (alternativ: mx00.kundenserver.de / mx01.kundenserver.de)")),
  value("ionos", "mx", "kundenserver.de", vendor(IONOS_MX_DE, "mx00.ionos.de / mx01.ionos.de (alternativ: mx00.kundenserver.de / mx01.kundenserver.de)")),
  // The page lists a third selector, s42582890, whose target answers NXDOMAIN (DoH, 2026-11-19):
  // it is not tried.
  value("ionos", "dkimSelectors", "s1-ionos", vendor(IONOS_DKIM, "s1-ionos._domainkey s1.dkim.ionos.com 1 hour")),
  value("ionos", "dkimSelectors", "s2-ionos", vendor(IONOS_DKIM, "s2-ionos._domainkey s2.dkim.ionos.com 1 hour")),
  value("ionos", "dkimTargets", "dkim.ionos.com", vendor(IONOS_DKIM, "s1-ionos._domainkey s1.dkim.ionos.com 1 hour")),

  value("gandi", "mx", "mail.gandi.net", vendor(GANDI_MX, "@ 10800 IN MX 10 spool.mail.gandi.net.")),
  value("gandi", "spfIncludes", "_mailcust.gandi.net", vendor(GANDI, '@ 10800 IN TXT "v=spf1 include:_mailcust.gandi.net ?all"')),
  value("gandi", "dkimSelectors", "gm1", vendor(GANDI, "gm1._domainkey 10800 IN CNAME gm1.gandimail.net.")),
  value("gandi", "dkimSelectors", "gm2", vendor(GANDI, "gm2._domainkey 10800 IN CNAME gm2.gandimail.net.")),
  value("gandi", "dkimSelectors", "gm3", vendor(GANDI, "gm3._domainkey 10800 IN CNAME gm3.gandimail.net.")),
  value("gandi", "dkimTargets", "gandimail.net", vendor(GANDI, "gm1._domainkey 10800 IN CNAME gm1.gandimail.net.")),

  value("migadu", "mx", "migadu.com", vendor(MIGADU, '"value": "aspmx1.migadu.com"')),
  value("migadu", "spfIncludes", "spf.migadu.com", vendor(MIGADU, '"value": "v=spf1 include:spf.migadu.com -all"')),
  value("migadu", "dkimSelectors", "key1", vendor(MIGADU, '"name": "key1._domainkey", "type": "cname", "value": "key1.mydomain.org._domainkey.migadu.com."')),
  value("migadu", "dkimSelectors", "key2", vendor(MIGADU, '"name": "key2._domainkey", "type": "cname", "value": "key2.mydomain.org._domainkey.migadu.com."')),
  value("migadu", "dkimSelectors", "key3", vendor(MIGADU, '"name": "key3._domainkey", "type": "cname", "value": "key3.mydomain.org._domainkey.migadu.com."')),
  value("migadu", "dkimTargets", "migadu.com", vendor(MIGADU, '"value": "key1.mydomain.org._domainkey.migadu.com."')),

  value("namecheap-private-email", "mx", "privateemail.com", vendor(NAMECHEAP, "@ MX 10 mx1.privateemail.com")),
  value("namecheap-private-email", "spfIncludes", "spf.privateemail.com", vendor(NAMECHEAP, "@ TXT v=spf1 include:spf.privateemail.com ~all")),
  // privateemail is the TXT the DKIM page gives; default, used before 2026-06-02, is no provider's.
  value("namecheap-private-email", "dkimSelectors", "privateemail", vendor(NAMECHEAP_DKIM, "Host : privateemail._domainkey Record type : TXT")),

  value("purelymail", "mx", "purelymail.com", vendor(PURELYMAIL, 'Put @ on the "Name" field and mailserver.purelymail.com on the Mail Server field.')),
  value("purelymail", "spfIncludes", "_spf.purelymail.com", vendor(PURELYMAIL, 'Put @ on the "Name" field and v=spf1 include:_spf.purelymail.com ~all on the Content field.')),
  value("purelymail", "dkimSelectors", "purelymail1", vendor(PURELYMAIL, 'Put purelymail1._domainkey on the "Name" field and key1.dkimroot.purelymail.com on the Content field.')),
  value("purelymail", "dkimSelectors", "purelymail2", vendor(PURELYMAIL, 'Put purelymail2._domainkey on the "Name" field and key2.dkimroot.purelymail.com on the Content field.')),
  value("purelymail", "dkimSelectors", "purelymail3", vendor(PURELYMAIL, 'Put purelymail3._domainkey on the "Name" field and key3.dkimroot.purelymail.com on the Content field.')),
  value("purelymail", "dkimTargets", "dkimroot.purelymail.com", vendor(PURELYMAIL, 'Put purelymail1._domainkey on the "Name" field and key1.dkimroot.purelymail.com on the Content field.')),

  value("mailbox-org", "mx", "mailbox.org", vendor(MAILBOX_MX, "example-domain.com MX 10 mxext1.mailbox.org.")),
  value("mailbox-org", "spfIncludes", "mailbox.org", vendor(MAILBOX, "@ TXT v=spf1 include:mailbox.org ~all SPF")),
  value("mailbox-org", "dkimSelectors", "mbo0001", vendor(MAILBOX, "MBO0001._domainkey.example.com CNAME MBO0001._domainkey.mailbox.org.")),
  value("mailbox-org", "dkimSelectors", "mbo0002", vendor(MAILBOX, "MBO0002._domainkey.example.com CNAME MBO0002._domainkey.mailbox.org.")),
  value("mailbox-org", "dkimSelectors", "mbo0003", vendor(MAILBOX, "MBO0003._domainkey.example.com CNAME MBO0003._domainkey.mailbox.org.")),
  value("mailbox-org", "dkimSelectors", "mbo0004", vendor(MAILBOX, "MBO0004._domainkey.example.com CNAME MBO0004._domainkey.mailbox.org.")),
  value("mailbox-org", "dkimTargets", "mailbox.org", vendor(MAILBOX, "MBO0001._domainkey.example.com CNAME MBO0001._domainkey.mailbox.org.")),

  value("strato", "mx", "rzone.de", vendor(STRATO, "MX-Record : smtpin.rzone.de")),
  // With Strato alone the page gives redirect=, the record fixes.ts writes (flagSources,
  // spfRedirect); with other senders, this include.
  value("strato", "spfIncludes", "_spf.strato.com", vendor(STRATO, "Sollen die STRATO Mailserver weiterhin E-Mails versenden dürfen, nehmen Sie include:_spf.strato.com in Ihren Eintrag auf.")),
  value("strato", "dkimSelectors", "strato-dkim-0002", vendor(STRATO, "strato-dkim-0002._domainkey.meinedomain.tld CNAME strato-dkim-0002._domainkey.rzone.de.")),
  value("strato", "dkimSelectors", "strato-dkim-0003", vendor(STRATO, "strato-dkim-0003._domainkey.meinedomain.tld CNAME strato-dkim-0003._domainkey.rzone.de.")),
  // The target is itself a CNAME to strato-dkim-0002._domainkey.strato.de (DoH, 2026-11-19);
  // rzone.de is the first name of the chain.
  value("strato", "dkimTargets", "rzone.de", vendor(STRATO, "strato-dkim-0002._domainkey.meinedomain.tld CNAME strato-dkim-0002._domainkey.rzone.de.")),

  value("mailerlite", "dkimSelectors", "litesrv", vendor(MAILERLITE, "In the Name field box, add litesrv._domainkey .")),
  value("mailerlite", "dkimTargets", "mlsend.com", vendor(MAILERLITE, "In the Target field box, paste the DKIM value litesrv._domainkey.mlsend.com .")),

  value("help-scout", "dkimSelectors", "strong1", vendor(HELPSCOUT, "strong1._domainkey.yourdomain.com will point to strong1._domainkey.helpscout.net")),
  value("help-scout", "dkimSelectors", "strong2", vendor(HELPSCOUT, "strong2._domainkey.yourdomain.com will point to strong2._domainkey.helpscout.net")),
  value("help-scout", "dkimTargets", "helpscout.net", vendor(HELPSCOUT, "strong1._domainkey.yourdomain.com will point to strong1._domainkey.helpscout.net")),

  value("constant-contact", "dkimSelectors", "ctct1", vendor(CTCT, "For CNAME, the record name should be input as “ctct1._domainkey” and “ctct2_domainkey”")),
  value("constant-contact", "dkimSelectors", "ctct2", vendor(CTCT, "For CNAME, the record name should be input as “ctct1._domainkey” and “ctct2_domainkey”")),
  value("constant-contact", "dkimTargets", "ccsend.com", vendor(CTCT_TROUBLESHOOTING, "For CNAME records, it points back to ccsend.com (100._domainkey.dkim1.ccsend.com or 200._domainkey.dkim2.ccsend.com).")),

  value("squarespace", "dkimSelectors", "squarespace", vendor(SQUARESPACE, "CNAME squarespace._domainkey squarespace-domainkey.squarespace-mail.com")),
  value("squarespace", "dkimTargets", "squarespace-mail.com", vendor(SQUARESPACE, "CNAME squarespace._domainkey squarespace-domainkey.squarespace-mail.com")),

  value("mailpoet", "dkimSelectors", "mailpoet1", vendor(MAILPOET, "leaving them as ” mailpoet1._domainkey”, “mailpoet2._domainkey”, “_mailpoet”, and “_dmarc”")),
  value("mailpoet", "dkimSelectors", "mailpoet2", vendor(MAILPOET, "leaving them as ” mailpoet1._domainkey”, “mailpoet2._domainkey”, “_mailpoet”, and “_dmarc”")),

  value("emma", "dkimSelectors", "e2ma-k1", vendor(EMMA, "e2ma-k1._domainkey e2ma-k1.dkim.e2ma.net.")),
  value("emma", "dkimSelectors", "e2ma-k2", vendor(EMMA, "e2ma-k2._domainkey e2ma-k2.dkim.e2ma.net.")),
  value("emma", "dkimSelectors", "e2ma-k3", vendor(EMMA, "e2ma-k3._domainkey e2ma-k3.dkim.e2ma.net.")),
  value("emma", "dkimTargets", "dkim.e2ma.net", vendor(EMMA, "e2ma-k1._domainkey e2ma-k1.dkim.e2ma.net.")),
  ...moreValues,

];

const RESEND_SES = "The MX and the include on the send subdomain are those of Amazon SES, listed under Amazon SES.";

/** One entry per empty list of providerList, in its order. */
export const emptyFields: readonly EmptyField[] = [
  empty("google-workspace", "dkimTargets", none(GOOGLE_DKIM, TXT_KEY)),
  empty("zoho-mail", "dkimTargets", none(ZOHO_DKIM, TXT_KEY)),
  empty("proton-mail", "dkimTargets", none(PROTON_CLOUDFLARE, "The CNAME target is copied from the Proton Mail console; the page does not give it.")),
  empty("cloudflare-email-routing", "dkimTargets", none(CLOUDFLARE, TXT_KEY)),
  empty("amazon-ses", "dkimSelectors", none(SES_IDENTITIES, "Easy DKIM gives three CNAME records per domain in the SES console; their names are tokens no list can hold.")),
  empty("mailgun", "dkimTargets", unused(MAILGUN_ROTATE, "Its only DKIM CNAME target is for the pdk1 and pdk2 selectors of Automatic Sender Security, which this check does not look up; none is given for smtp, mx, pic, krs or mailo.", "dkim1.mailgun.com", "the target where you point back to Mailgun will look something like pdk1._domainkey.9d876.dkim1.mailgun.com")),
  empty("postmark", "mx", none(POSTMARK_RETURN_PATH, "The custom Return-Path is a CNAME to pm.mtasv.net, not an MX.")),
  empty("postmark", "spfIncludes", none(POSTMARK_RETURN_PATH)),
  empty("postmark", "dkimSelectors", none(POSTMARK_DKIM, "The DKIM record, its name included, is shown in the Postmark account.")),
  empty("postmark", "dkimTargets", none(POSTMARK_DKIM, TXT_KEY)),
  // One criterion with Amazon SES: a value belongs to the provider whose service it names, on
  // whatever name the vendor asks for it.
  empty("resend", "mx", unused(RESEND, RESEND_SES, "amazonses.com", '"name": "send", "type": "MX", "ttl": "Auto", "status": "not_started", "value": "feedback-smtp.us-east-1.amazonses.com"')),
  empty("resend", "spfIncludes", unused(RESEND, RESEND_SES, "amazonses.com", '"name": "send", "value": "v=spf1 include:amazonses.com ~all"')),
  empty("resend", "dkimTargets", none(RESEND, TXT_KEY)),
  empty("brevo", "mx", none(BREVO)),
  empty("brevo", "spfIncludes", none(BREVO)),
  empty("brevo", "dkimTargets", none(BREVO, "The value of each record is copied from the Brevo account; the page does not give it.")),
  empty("mailchimp", "mx", none(MAILCHIMP)),
  empty("mailchimp", "spfIncludes", none(MAILCHIMP, "The page asks for 2 CNAME records and 1 TXT record, the DMARC one, and no SPF.")),
  empty("klaviyo", "mx", none(KLAVIYO_SETUP, "Only a service sending subdomain gets an MX record, and Klaviyo manages it.")),
  empty("klaviyo", "spfIncludes", none(KLAVIYO_SETUP)),
  empty("zendesk", "mx", none(ZENDESK_SPF)),
  empty("mandrill", "mx", none(MANDRILL)),
  empty("mandrill", "spfIncludes", none(MANDRILL, "Its return path is its own, mandrillapp.com, unless the sender points it to a domain of theirs.")),
  empty("ionos", "spfIncludes", unused(IONOS_SPF, "The page, on ionos.com, gives include:_spf-us.ionos.com, and the French and Spanish ones _spf-eu.ionos.com (2026-11-24). No page maps every country to its include, so the check does not suggest one.", "_spf-us.ionos.com", "create a TXT record for your domain with the following value: v=spf1 include:_spf-us.ionos.com ~all")),
  empty("namecheap-private-email", "dkimTargets", none(NAMECHEAP_DKIM, TXT_KEY)),
  empty("mailerlite", "mx", none(MAILERLITE)),
  empty("mailerlite", "spfIncludes", none(MAILERLITE)),
  empty("help-scout", "mx", none(HELPSCOUT)),
  empty("help-scout", "spfIncludes", unused(HELPSCOUT_SPF, "Help Scout says the include:helpscoutemail.com it once asked for can be removed.", "helpscoutemail.com", "You can safely remove include:helpscoutemail.com from your SPF record if you added it previously.")),
  empty("constant-contact", "mx", none(CTCT)),
  empty("constant-contact", "spfIncludes", none(CTCT)),
  empty("squarespace", "mx", none(SQUARESPACE)),
  empty("squarespace", "spfIncludes", none(SQUARESPACE)),
  empty("mailpoet", "mx", none(MAILPOET)),
  empty("mailpoet", "spfIncludes", none(MAILPOET)),
  // Both CNAME of the 8 domains of the sample with a MailPoet key point to sendingservice.net;
  // measured only, so no dkimTargets.
  empty("mailpoet", "dkimTargets", none(MAILPOET, "The page names the selectors but not their target.")),
  empty("emma", "mx", none(EMMA)),
  empty("emma", "spfIncludes", none(EMMA)),
  ...moreEmptyFields,

];

/** The selectors of SELECTORS that are in no provider's list, with who uses them. */
export const otherSelectors: Readonly<Record<string, Backing & { usedBy: string }>> = {
  // Brevo's older TXT, and Yandex 360's selector: 240 domains of the sample have a TXT key here and
  // at most 27 name brevo or sendinblue in the apex SPF or MX, so it is tried but names no
  // provider.
  mail: { usedBy: "Brevo", ...vendor(BREVO_API, '"dkim_record": { "host_name": "mail._domainkey", "type": "TXT"') },
  default: { usedBy: "cPanel", ...vendor(CPANEL, 'By default, cPanel systems use "default._domainkey" as the DKIM selector.') },
  dkim: { usedBy: "rspamd", ...vendor(RSPAMD, '# Default selector to use selector = "dkim";') },
  mandrill: { usedBy: "Mailchimp Transactional (Mandrill)", ...dns(READ_2026_11_20, "mandrillapp.com") },
  mailjet: { usedBy: "Mailjet", ...vendor(MAILJET, '"DKIMRecordName": "mailjet._domainkey.example.com."') },
  intercom: { usedBy: "Intercom", ...vendor(INTERCOM, "Selector : intercom Domain : yourdomain.com") },
  cm: { usedBy: "Campaign Monitor", ...vendor(CAMPAIGN_MONITOR, "Fourth level domains — For example, cm._domainkey.example.com.") },
  x: { usedBy: "DirectAdmin", ...vendor(DIRECTADMIN, "dkim_selector=x The selector to be used for dkim records.") },
  acdkim1: { usedBy: "ActiveCampaign", ...vendor(ACTIVECAMPAIGN, "like acdkim1._domainkey (most common)") },
  "cf-bounce": { usedBy: "Cloudflare Email Sending", ...vendor(CLOUDFLARE, "TXT cf-bounce._domainkey.yourdomain.com") },
  // “il selector utilizzato è a1” (3 domains of the sample have a key only there).
  a1: { usedBy: "Aruba", ...vendor(ARUBA, "Per la configurazione DKIM del servizio email Aruba descritta in questa guida, il selector utilizzato è a1 .") },
};

/**
 * The source of each selector of SELECTORS, in its order: a selector in a provider's list has the
 * source of that value, so the two never disagree; any other has its own in otherSelectors.
 */
export const selectorSources: readonly SelectorSource[] = SELECTORS.map((selector) => {
  const own = valueSources.find((s) => s.field === "dkimSelectors" && s.value === selector);
  if (own) {
    const { provider: _p, field: _f, value: _v, ...backing } = own;
    return { selector, ...backing };
  }
  const other = otherSelectors[selector];
  if (!other) throw new Error(`selector ${selector} has no source: give it one in valueSources or otherSelectors`);
  return { selector, ...other };
});

/** The vendor's words behind each flag of providerList (FlagSource["flag"]). */
export const flagSources: readonly FlagSource[] = [
  // Its default MAIL FROM is a subdomain of amazonses.com, and a custom one is a subdomain of the
  // sender's (SES_MAIL_FROM): the apex never shows SES, so a key of it asks nothing.
  { provider: "amazon-ses", flag: "sendOnly", ...SES_MAIL_FROM, quote: "Messages that you send through Amazon SES automatically use a subdomain of amazonses.com as the default MAIL FROM domain." },
  // Strato alone: the page's record, which fixes.ts writes for a domain with Strato's MX and no
  // SPF.
  { provider: "strato", flag: "spfRedirect", ...STRATO, quote: "SPF : v=spf1 redirect=_spf.strato.com Dieser Eintrag gilt, wenn ausschließlich STRATO Mailserver E-Mails Ihrer Domain versenden." },
  // Its records at the apex route incoming mail; sending as the domain is Email Sending, on the
  // records of a cf-bounce subdomain.
  { provider: "cloudflare-email-routing", flag: "receiveOnly", ...CLOUDFLARE, quote: "Email Routing DNS records are configured on the root domain. Purpose : Route incoming emails to Cloudflare's mail servers." },
  // The return path is a subdomain of the customer, with or without automated security.
  { provider: "sendgrid", flag: "sendOnly", ...SENDGRID, quote: "em[0000].example.com [u00000000].[wl000].sendgrid.net SPF" },
  // With the engine on the sample, 107 of the 171 domains with a TXT key at a Mailgun selector got
  // “Does Mailgun still send mail?”.
  { provider: "mailgun", flag: "sendOnly", ...MAILGUN_FAQ, quote: "At Mailgun, our standard recommendation is to have your sending domain be a subdomain off your main root domain." },
  // The include is optional, and 53 of the 147 domains of the sample with a Zendesk key do not name
  // zendesk in the apex SPF.
  { provider: "zendesk", flag: "sendOnly", ...ZENDESK_SPF, quote: "So, do you have to allow Zendesk to send email on behalf of your email domain? The short answer is: No." },
  ...moreFlags,
];
