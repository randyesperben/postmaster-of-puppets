// The rest of the provider sources, in the form of index.ts and kept apart from it so neither file
// grows too long: index.ts takes these entries into its own lists, and nothing else imports this
// file. Every vendor page here was read on its `read` date and each quote checked against that
// day's text. Each link sits in a string of its page constant, as in index.ts, so the tests and a
// script can read the links of both files.
import { SES_RECEIVING_REGIONS } from "../../src/providers.ts";
import type { EmptyField, FlagSource, ValueSource } from "./index.ts";
import { dns, empty, none, page, READ_2026_11_20, READ_2026_11_24, TXT_KEY, unused, value, vendor } from "./builders.ts";

// Two pages index.ts quotes too, defined here for the empty lists below: index.ts imports this
// file, which takes only types from it.
export const ACTIVECAMPAIGN = page("https://help.activecampaign.com/hc/en-us/articles/360015584680-Set-up-your-sending-domain", READ_2026_11_20);
export const ARUBA = page("https://guide.aruba.it/hosting-e-domini/email/gestione-email/sicurezza-e-storico-accessi/usare-dkim", READ_2026_11_20);

const SES_RECEIVING = page("https://docs.aws.amazon.com/general/latest/gr/ses.html", READ_2026_11_24);
const YANDEX_MX = page("https://yandex.com/support/yandex-360/business/admin/en/domains/dns/mx.html", READ_2026_11_24);
const YANDEX_SPF = page("https://yandex.com/support/yandex-360/business/admin/en/domains/dns/spf.html", READ_2026_11_24);
const YANDEX_DKIM = page("https://yandex.com/support/yandex-360/business/admin/en/domains/dns/dkim.html", READ_2026_11_24);
const TENCENT_MX = page("https://open.work.weixin.qq.com/help2/pc/14447", READ_2026_11_24);
const TENCENT_SPF = page("https://open.work.weixin.qq.com/help2/pc/19817", READ_2026_11_24);
const ALIBABA = page("https://help.aliyun.com/zh/document_detail/36723.html", READ_2026_11_24);
const OVH_MX = page("https://docs.ovhcloud.com/en/guides/web-cloud/domains/dns-zone-mx", READ_2026_11_24);
const OVH_SPF = page("https://docs.ovhcloud.com/en/guides/web-cloud/domains/dns-zone-spf", READ_2026_11_24);
const OVH_DKIM = page("https://docs.ovhcloud.com/en/guides/web-cloud/domains/dns-zone-dkim", READ_2026_11_24);
const HOVER_MX = page("https://support.hover.com/support/solutions/articles/201000064726", READ_2026_11_24);
const HOVER_SPF = page("https://support.hover.com/support/solutions/articles/201000064663", READ_2026_11_24);
const VK_MX = page("https://workspace.vk.ru/docs/saas/WorkMail/Startup/mx-record/", READ_2026_11_24);
const VK_SPF = page("https://workspace.vk.ru/docs/saas/WorkMail/Startup/spf-record/", READ_2026_11_24);
const RACKSPACE = page("https://docs.rackspace.com/docs/set-up-dns-records-for-cloud-office-email", READ_2026_11_24);
const SALESFORCE_SPF = page("https://help.salesforce.com/s/articleView?id=000006347&type=1", READ_2026_11_24);
const SALESFORCE_DKIM = page("https://help.salesforce.com/s/articleView?id=sf.emailadmin_create_secure_dkim.htm&type=5", READ_2026_11_24);
const ARUBA_SPF = page("https://guide.aruba.it/hosting-e-domini/email/gestione-email/sicurezza-e-storico-accessi/usare-spf", READ_2026_11_24);
const NOMINALIA = page("https://www.nominalia.com/help/dns-email-como-crear-registros-spf-dkim-y-dmarc/", READ_2026_11_24);
const REGISTER_EMAIL = page("https://www.register.it/assistenza/problemi-con-le-email/", READ_2026_11_24);
// Register.it's own page with the include its fix writes.
const REGISTER_SPF = page("https://www.register.it/help/spf-dkim-gmail/", READ_2026_11_24);
const INFOMANIAK_MX = page("https://www.infomaniak.com/en/support/faq/2110/manage-mx-records", READ_2026_11_24);
const INFOMANIAK_SPF = page("https://www.infomaniak.com/en/support/faq/2199/manage-spf-records", READ_2026_11_24);
const LOCAWEB = page("https://www.locaweb.com.br/ajuda/wiki/como-configurar-o-mx-e-mail-locaweb/", READ_2026_11_24);
const TRANSIP = page("https://www.transip.eu/knowledgebase/527-the-dns-settings-web-hosting/", READ_2026_11_24);
const NETCUP = page("https://www.netcup.com/en/helpcenter/documentation/web-hosting/webhosting-dns", READ_2026_11_24);
const ALLINKL_MX = page("https://all-inkl.com/en/support/tutorials/kas/tools/dns-tools/how-to-change-the-mx-record-using-a-host-address_154.html", READ_2026_11_24);
const ALLINKL_SPF = page("https://all-inkl.com/en/support/tutorials/kas/tools/dns-tools/how-to-add-an-spf-record_482.html", READ_2026_11_24);
const CYBERFOLKS = page("https://cyberfolks.pl/pomoc/weryfikacja-nadawcy-wiadomosci-spf-dkim-dmarc/", READ_2026_11_24);
const IONOS_MX_ES = page("https://www.ionos.es/ayuda/index.php?id=19640", READ_2026_11_24);
const IONOS_MX_FR = page("https://www.ionos.fr/assistance/domaines/informations-generales-sur-les-parametres-dns/parametres-dns-par-defaut-pour-les-domaines-enregistres-chez-11-ionos/", READ_2026_11_24);
// The page of the same article in Spanish (…-42103) gives no values; this one, untranslated, does.
const GODADDY = page("https://www.godaddy.com/es-es/help/what-are-my-dns-settings-for-professional-email-powered-by-titan-42767", READ_2026_11_24);
const GODADDY_DKIM = page("https://www.godaddy.com/es-es/help/agregar-spf-dkim-y-dmarc-a-mi-dominio-para-professional-email-powered-by-titan-42437", READ_2026_11_24);
const ARSYS_DMARC = page("https://www.arsys.es/soporte#/articles/que-es-dmarc-y-como-activarlo----077d07ea-9751-4f80-abcc-36f6cd8d7fe6", READ_2026_11_24);
const ARSYS_DNS = page("https://www.arsys.es/soporte#/articles/servidores-dns-y-entradas-dns-que-son-y-como-funcionan----53c4623e-3c9b-4817-8eee-5cf807dfd224", READ_2026_11_24);
const HOSTNET_SPF = page("https://helpdesk.hostnet.nl/hc/nl-nl/articles/360015823697-Welk-SPF-record-kan-ik-instellen-als-ik-e-mails-verstuur-via-het-platform-van-Hostnet", READ_2026_11_24);
const HOSTNET_WIX = page("https://helpdesk.hostnet.nl/hc/nl-nl/articles/360014900838-Domeinnaam-koppelen-aan-Wix", READ_2026_11_24);
const ANTAGONIST = page("https://help.antagonist.nl/hc/nl/articles/8523986825617-Hoe-beheer-ik-DNS-records-in-DirectAdmin", READ_2026_11_24);
const NAMECHEAP_FORWARDING = page("https://www.namecheap.com/support/knowledgebase/article.aspx/308/2214/how-to-set-up-free-email-forwarding/", READ_2026_11_24);
const NAMECHEAP_MX = page("https://www.namecheap.com/support/knowledgebase/article.aspx/322/2237/how-can-i-set-up-mx-records-required-for-mail-service/", READ_2026_11_24);
const MIMECAST_GATEWAY = page("https://mimecastsupport.zendesk.com/hc/en-us/articles/34000417366675", READ_2026_11_24);
const MIMECAST_SPF = page("https://mimecastsupport.zendesk.com/hc/en-us/articles/34000792642963", READ_2026_11_24);
const BARRACUDA_SPF = page("https://documentation.campus.barracuda.com/wiki/spaces/EGD/pages/2855134", READ_2026_11_24);
const BARRACUDA_MX = page("https://documentation.campus.barracuda.com/wiki/spaces/EGD/pages/2851259", READ_2026_11_24);
const HORNETSECURITY = page("https://www.hornetsecurity.com/en/onboarding-information/", READ_2026_11_24);
const CISCO = page("https://docs.ces.cisco.com/docs/hostnames", READ_2026_11_24);
const MARKETO = page("https://experienceleague.adobe.com/en/docs/marketo/using/product-docs/email-marketing/deliverability/set-up-spf-and-dkim-for-your-email-deliverability", READ_2026_11_24);
const ELASTIC = page("https://help.elasticemail.com/en/articles/4934400-how-to-verify-your-domain", READ_2026_11_24);
const MAILCHANNELS = page("https://docs.mailchannels.com/outbound/spf-records.md", READ_2026_11_24);
const ACTIVECAMPAIGN_SPF = page("https://help.activecampaign.com/hc/en-us/articles/13063110494364", READ_2026_11_24);
const HOSTGATOR = page("https://suporte.hostgator.com.br/hc/pt-br/articles/30817482782099-Como-usar-o-e-mail-na-HostGator-e-o-site-em-outro-provedor", READ_2026_11_24);
const HETZNER = page("https://docs.hetzner.com/de/managed/domain-and-dns/dnsadministration/", READ_2026_11_24);
const HOSTEUROPE = page("https://www.hosteurope.de/faq/domains/verwaltung/spf_dkim_classic_hosting/", READ_2026_11_24);
const O2SWITCH = page("https://faq.o2switch.fr/cpanel/emails/delivrabilite-spf-dkim/", READ_2026_11_24);
const KINGHOST = page("https://king.host/wiki/artigo/dkim-spf-e-dmarc-como-garantir-a-seguranca-e-a-entrega-dos-seus-e-mails/", READ_2026_11_24);
const MIJNDOMEIN = page("https://mijndomein.zendesk.com/hc/nl/articles/360001163498-Je-domeinnaam-koppelen-aan-je-Wix-website-via-nameservers", READ_2026_11_24);
/** The name of each Region in the receiving table of SES_RECEIVING, as the page writes it. */
const SES_REGION_NAMES: Record<string, string> = {
  "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)", "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
  "af-south-1": "Africa (Cape Town)", "ap-southeast-3": "Asia Pacific (Jakarta)", "ap-south-1": "Asia Pacific (Mumbai)", "ap-northeast-3": "Asia Pacific (Osaka)",
  "ap-northeast-2": "Asia Pacific (Seoul)", "ap-southeast-1": "Asia Pacific (Singapore)", "ap-southeast-2": "Asia Pacific (Sydney)", "ap-northeast-1": "Asia Pacific (Tokyo)",
  "ca-central-1": "Canada (Central)", "eu-central-1": "Europe (Frankfurt)", "eu-west-1": "Europe (Ireland)", "eu-west-2": "Europe (London)",
  "eu-south-1": "Europe (Milan)", "eu-west-3": "Europe (Paris)", "eu-north-1": "Europe (Stockholm)", "il-central-1": "Israel (Tel Aviv)",
  "me-south-1": "Middle East (Bahrain)", "sa-east-1": "South America (São Paulo)",
};
const PER_CUSTOMER = "The selector is the customer’s own, so no list can hold it; a key under one typed is the provider’s by its CNAME target.";
const NOT_TRIED = "A selector of its own that the check does not try; a key there is found when typed, and is the provider’s by its CNAME target.";
// A note is public text in the provider dataset, so it holds no dates or names.

/** These providers' values, after those of index.ts. */
export const moreValues: readonly ValueSource[] = [
  ...SES_RECEIVING_REGIONS.map((r) => value("amazon-ses", "mx", `inbound-smtp.${r}.amazonaws.com`, vendor(SES_RECEIVING, `${SES_REGION_NAMES[r] ?? "-"} ${r} inbound-smtp.${r}.amazonaws.com`))),
  value("ionos", "mx", "ionos.es", vendor(IONOS_MX_ES, "mx00.ionos.es y mx01.ionos.es (o alternativamente mx00.1and1.es y mx01.1and1.es )")),
  value("ionos", "mx", "1and1.es", vendor(IONOS_MX_ES, "mx00.ionos.es y mx01.ionos.es (o alternativamente mx00.1and1.es y mx01.1and1.es )")),
  value("ionos", "mx", "1and1.fr", vendor(IONOS_MX_FR, "Serveur de messagerie 1 mx00.1and1.fr Serveur de messagerie 2 mx01.1and1.fr")),

  value("yandex-360", "mx", "mx.yandex.net", vendor(YANDEX_MX, "Value — mx.yandex.net.")),
  value("yandex-360", "spfIncludes", "_spf.yandex.net", vendor(YANDEX_SPF, "v=spf1 ip4:IP-1 ip4:IP-2 ip4:IP-3 include:_spf.yandex.net ~all")),
  value("tencent-exmail", "mx", "mxbiz1.qq.com", vendor(TENCENT_MX, "Record value: mxbiz1.qq.com; priority: 5 Record value: mxbiz2.qq.com; priority: 10")),
  value("tencent-exmail", "mx", "mxbiz2.qq.com", vendor(TENCENT_MX, "Record value: mxbiz1.qq.com; priority: 5 Record value: mxbiz2.qq.com; priority: 10")),
  value("tencent-exmail", "spfIncludes", "spf.mail.qq.com", vendor(TENCENT_SPF, "The TXT record value is: v=spf1 include:spf.mail.qq.com ~all.")),
  // Its standard records give mx1 to mx3.qiye.aliyun.com, and those of its group and legacy plans
  // mxn and mxw.mxhichina.com.
  value("alibaba-mail", "mx", "qiye.aliyun.com", vendor(ALIBABA, "@ MX 5 mx1.qiye.aliyun.com @ MX 10 mx2.qiye.aliyun.com @ MX 15 mx3.qiye.aliyun.com")),
  value("alibaba-mail", "mx", "mxhichina.com", vendor(ALIBABA, "@ MX 5 mxn.mxhichina.com @ MX 10 mxw.mxhichina.com")),
  value("alibaba-mail", "spfIncludes", "spf.qiye.aliyun.com", vendor(ALIBABA, "@ TXT v=spf1 include:spf.qiye.aliyun.com -all")),
  value("ovhcloud", "mx", "mail.ovh.net", vendor(OVH_MX, "@ 3600 MX 1 mx0.mail.ovh.net. @ 3600 MX 5 mx1.mail.ovh.net.")),
  value("ovhcloud", "spfIncludes", "mx.ovh.com", vendor(OVH_SPF, "For example, the OVHcloud SPF is: v=spf1 include:mx.ovh.com ~all")),
  value("ovhcloud", "dkimTargets", "dkim.mail.ovh.net", vendor(OVH_DKIM, "ovhmo3456789-selector1._domainkey.domain.tld CNAME ovhmo3456789-selector1._domainkey.123403.aj.dkim.mail.ovh.net.")),
  value("hover", "mx", "mx.hover.com.cust.hostedemail.com", vendor(HOVER_MX, "Mail server mx.hover.com.cust.hostedemail.com")),
  value("vk-workspace", "mx", "emx.mail.ru", vendor(VK_MX, "Значение : emx.mail.ru")),
  // The page gives only redirect= (flagSources, spfRedirect); with other senders, the same name as
  // an include.
  value("vk-workspace", "spfIncludes", "_spf.mail.ru", vendor(VK_SPF, "v=spf1 redirect=_spf.mail.ru")),
  value("rackspace", "mx", "emailsrvr.com", vendor(RACKSPACE, "MX @ or left blank mx1.emailsrvr.com 10")),
  value("rackspace", "spfIncludes", "emailsrvr.com", vendor(RACKSPACE, "TXT @ or left blank v=spf1 include:emailsrvr.com ~all")),
  value("salesforce", "spfIncludes", "_spf.salesforce.com", vendor(SALESFORCE_SPF, "The appropriate entry to include in your SPF record when sending mail from the Salesforce application is _spf.salesforce.com.")),
  value("salesforce", "dkimTargets", "custdkim.salesforce.com", vendor(SALESFORCE_DKIM, "example-sf-a._domainkey.example.com. 3600 IN CNAME example-sf-a.k4tyd2.custdkim.salesforce.com.")),
  value("aruba", "spfIncludes", "_spf.aruba.it", vendor(ARUBA_SPF, "Se invii email esclusivamente attraverso i server di posta Aruba, puoi utilizzare il seguente record SPF: v=spf1 include:_spf.aruba.it -all")),
  value("register-nominalia", "mx", "mail.register.it", vendor(REGISTER_EMAIL, "Hai impostato i DNS di Register.it e hai il record MX “mail.register.it”?")),
  value("register-nominalia", "dkimTargets", "securemail.pro", vendor(NOMINALIA, "Nombre: key-nomi001._domainkey.midominio.com Tipo: CNAME Valor: key-nomi001._domainkey.securemail.pro")),
  value("infomaniak", "mx", "mta-gw.infomaniak.ch", vendor(INFOMANIAK_MX, "Target: mta-gw.infomaniak.ch Priority: 5")),
  value("infomaniak", "spfIncludes", "spf.infomaniak.ch", vendor(INFOMANIAK_SPF, "Infomaniak automatically installs this type of record when creating a Mail Service on your domain (strict SPF): v=spf1 include:spf.infomaniak.ch -all")),
  value("locaweb", "mx", "locaweb.com.br", vendor(LOCAWEB, ". MX 10 mx.b.locaweb.com.br . MX 10 mx.core.locaweb.com.br . MX 20 mx.a.locaweb.com.br . MX 20 mx.jk.locaweb.com.br")),
  value("locaweb", "spfIncludes", "_spf.locaweb.com.br", vendor(LOCAWEB, ". TXT 0 v=spf1 include:_spf.locaweb.com.br -all")),
  value("transip", "mx", "mx.transip.email", vendor(TRANSIP, "Name: @ Type: MX Value: 10 mx.transip.email.")),
  value("transip", "spfIncludes", "_spf.transip.email", vendor(TRANSIP, "Name: @ Type: TXT Value: v=spf1 include:_spf.transip.email ~all")),
  value("transip", "dkimTargets", "transip.email", vendor(TRANSIP, "Name: transip-A._domainkey Type: CNAME Value: _dkim-A.transip.email.")),
  value("netcup", "spfIncludes", "_spf.webhosting.systems", vendor(NETCUP, "Host: @ Type: TXT Destination: v=spf1 mx a include:_spf.webhosting.systems ~all")),
  value("netcup", "dkimTargets", "webhosting.systems", vendor(NETCUP, "Host: key1._domainkey Type: CNAME Destination: key1._domainkey.webhosting.systems")),
  // The host before kasserver.com is the customer's login.
  value("all-inkl", "mx", "kasserver.com", vendor(ALLINKL_MX, "delete the default MX record that points to <your-login>.kasserver.com")),
  value("all-inkl", "spfIncludes", "spf.kasserver.com", vendor(ALLINKL_SPF, 'Example entry: yourdomain.com. IN TXT "v=spf1 a mx include:spf.kasserver.com ~all"')),
  value("cyber-folks", "spfIncludes", "_spf.cyberfolks.pl", vendor(CYBERFOLKS, "twojadomena.pl TXT v=spf1 a mx include:_spf.cyberfolks.pl -all")),
  // Professional Email (Titan); Microsoft 365 from GoDaddy writes the same include, with
  // Microsoft's MX.
  value("godaddy", "mx", "smtp.secureserver.net", vendor(GODADDY, "the MX and TXT records are the same for all users and should be as follows: 2 MX records: Host Prioridad Objetivo @ 0 smtp.secureserver.net @ 10 mailstore1.secureserver.net")),
  value("godaddy", "mx", "mailstore1.secureserver.net", vendor(GODADDY, "the MX and TXT records are the same for all users and should be as follows: 2 MX records: Host Prioridad Objetivo @ 0 smtp.secureserver.net @ 10 mailstore1.secureserver.net")),
  value("godaddy", "spfIncludes", "secureserver.net", vendor(GODADDY, "1 TXT record for SPF: Nombre Valor TXT @ v=spf1 include:secureserver.net -all")),
  value("arsys", "spfIncludes", "_spf.serviciodecorreo.es", vendor(ARSYS_DMARC, "Busca una entrada de tipo TXT con el siguiente valor: v=spf1 include:_spf.serviciodecorreo.es ~all")),
  value("hostnet", "spfIncludes", "_spf.hostnet.nl", vendor(HOSTNET_SPF, "Met het volgende SPF-record zorg je dat jouw domein alleen e-mails verzendt vanaf het platform van Hostnet: v=spf1 a mx include:_spf.hostnet.nl -all")),
  value("antagonist", "spfIncludes", "_spf.webhostingserver.nl", vendor(ANTAGONIST, 'voorbeeld.nl. TXT "v=spf1 include:_spf.webhostingserver.nl ~all"')),
  value("antagonist", "dkimTargets", "dkim.webhostingserver.nl", vendor(ANTAGONIST, "whs1._domainkey CNAME abcdef12345hijklmnop.whs1.dkim.webhostingserver.nl.")),
  // Its page shows the include only in a screenshot, with no text to quote (read 2026-11-24), so
  // the value is the one seen in DNS, by DoH that day on easywp.com, a service of Namecheap's own.
  value("namecheap-email-forwarding", "spfIncludes", "spf.efwd.registrar-servers.com", dns(READ_2026_11_24, "easywp.com")),

  value("mimecast", "mx", "mimecast.com", vendor(MIMECAST_GATEWAY, "MX records (inbound) Europe (Excluding Germany) eu-smtp-inbound-1.mimecast.com eu-smtp-inbound-2.mimecast.com")),
  value("mimecast", "mx", "mimecast.co.za", vendor(MIMECAST_GATEWAY, "South Africa za-smtp-inbound-1.mimecast.co.za za-smtp-inbound-2.mimecast.co.za")),
  value("mimecast", "mx", "mimecast-offshore.com", vendor(MIMECAST_GATEWAY, "Offshore je-smtp-inbound-1.mimecast-offshore.com je-smtp-inbound-2.mimecast-offshore.com")),
  // The part before ess.barracudanetworks.com is the account's.
  value("barracuda", "mx", "ess.barracudanetworks.com", vendor(BARRACUDA_MX, "mydomain.com. 21600 IN MX 99 xxxxxxx.ess.barracudanetworks.com.")),
  // Its pages show only the US name; the regional ones are as seen in DNS, by DoH that day.
  value("barracuda", "mx", "ess.de.barracudanetworks.com", dns(READ_2026_11_24, "myhermes.de", "unesco.de")),
  value("barracuda", "mx", "ess.uk.barracudanetworks.com", dns(READ_2026_11_24, "britishmuseum.org", "essex.ac.uk")),
  value("barracuda", "mx", "ess.au.barracudanetworks.com", dns(READ_2026_11_24, "une.edu.au")),
  value("hornetsecurity", "mx", "hornetsecurity.com", vendor(HORNETSECURITY, "MX priority 10 mx01.hornetsecurity.com MX priority 20 mx02.hornetsecurity.com MX priority 30 mx03.hornetsecurity.com MX priority 40 mx04.hornetsecurity.com")),
  // A gateway's own include says the domain sends through it; its regional ones sit under these
  // names (Mimecast's eu._netblocks.mimecast.com and the like), or are listed one by one
  // (Barracuda).
  value("mimecast", "spfIncludes", "_netblocks.mimecast.com", vendor(MIMECAST_SPF, "Global (includes all the above) v=spf1 include:_netblocks.mimecast.com ~all")),
  value("barracuda", "spfIncludes", "spf.ess.barracudanetworks.com", vendor(BARRACUDA_SPF, "US (United States) include:spf.ess.barracudanetworks.com -all")),
  value("barracuda", "spfIncludes", "spf.ess.au.barracudanetworks.com", vendor(BARRACUDA_SPF, "AU (Australia) include:spf.ess.au.barracudanetworks.com -all")),
  value("barracuda", "spfIncludes", "spf.ess.ca.barracudanetworks.com", vendor(BARRACUDA_SPF, "CA (Canada) include:spf.ess.ca.barracudanetworks.com -all")),
  value("barracuda", "spfIncludes", "spf.ess.de.barracudanetworks.com", vendor(BARRACUDA_SPF, "DE (Germany) include:spf.ess.de.barracudanetworks.com -all")),
  value("barracuda", "spfIncludes", "spf.ess.in.barracudanetworks.com", vendor(BARRACUDA_SPF, "IN (India) include:spf.ess.in.barracudanetworks.com -all")),
  value("barracuda", "spfIncludes", "spf.ess.uk.barracudanetworks.com", vendor(BARRACUDA_SPF, "UK (United Kingdom) include:spf.ess.uk.barracudanetworks.com -all")),
  value("hornetsecurity", "spfIncludes", "spf.hornetsecurity.com", vendor(HORNETSECURITY, "The following setting is recommended: v=spf1 include:spf.hornetsecurity.com ~all")),
  // The allocation and the region before iphmx.com are the customer's.
  value("cisco-secure-email", "mx", "iphmx.com", vendor(CISCO, "mx1.<alloc>(.<region>).iphmx.com “mx1” will list all IP Addresses used in the MX Records")),
  value("marketo", "spfIncludes", "mktomail.com", vendor(MARKETO, "[domain] IN TXT v=spf1 mx ip4:[corpIP] include:mktomail.com ~all")),
  value("elastic-email", "spfIncludes", "_spf.elasticemail.com", vendor(ELASTIC, "Value: v=spf1 a mx include:_spf.elasticemail.com ~all")),
  value("mailchannels", "spfIncludes", "relay.mailchannels.net", vendor(MAILCHANNELS, "If you already have an SPF record, add `include:relay.mailchannels.net` to it")),
  value("activecampaign", "spfIncludes", "emsd1.com", vendor(ACTIVECAMPAIGN_SPF, "How to add ActiveCampaign’s include (include:emsd1.com) to an existing SPF record?")),
  // The server's name before your-server.de is the customer's.
  value("hetzner", "mx", "your-server.de", vendor(HETZNER, "@ IN MX 10 <server name>.your-server.de.")),
  value("host-europe", "spfIncludes", "spf.server-he.de", vendor(HOSTEUROPE, "Der Standard SPF-Record für die Classic Hosting Domains lautet: v=spf1 a mx include:spf.server-he.de -all")),
  value("o2switch", "spfIncludes", "spf.jabatus.fr", vendor(O2SWITCH, "Le seul SPF à utiliser pour envoyer des e-mails depuis nos services est : include:spf.jabatus.fr")),
  value("kinghost", "spfIncludes", "_spf.kinghost.net", vendor(KINGHOST, "Clientes : v=spf1 include:_spf.kinghost.net -all Revendas : v=spf1 include:_spf.uni5.net -all")),
  value("kinghost", "spfIncludes", "_spf.uni5.net", vendor(KINGHOST, "Clientes : v=spf1 include:_spf.kinghost.net -all Revendas : v=spf1 include:_spf.uni5.net -all")),
  value("mijndomein", "mx", "mx1.mijndomein.nl", vendor(MIJNDOMEIN, "Type: MX Prioriteit: 10 Hostnaam: leeg laten Waarde: mx1.mijndomein.nl")),
  value("mijndomein", "mx", "mx2.mijndomein.nl", vendor(MIJNDOMEIN, "Type: MX Prioriteit: 20 Hostnaam: leeg laten Waarde: mx2.mijndomein.nl")),
  value("mijndomein", "spfIncludes", "spf.mijndomeinhosting.nl", vendor(MIJNDOMEIN, "Type: TXT Hostnaam: leeg laten Waarde: v=spf1 a mx include:spf.mijndomeinhosting.nl ~all")),
];

/** These providers' empty lists, after those of index.ts. */
export const moreEmptyFields: readonly EmptyField[] = [
  empty("yandex-360", "dkimSelectors", unused(YANDEX_DKIM, "mail is Brevo’s older selector too, so it is tried but names no provider.", "mail", "Subdomain name (or Host ) — mail._domainkey .")),
  empty("yandex-360", "dkimTargets", none(YANDEX_DKIM, TXT_KEY)),
  empty("tencent-exmail", "dkimSelectors", none(TENCENT_SPF)),
  empty("tencent-exmail", "dkimTargets", none(TENCENT_SPF)),
  empty("alibaba-mail", "dkimSelectors", unused(ALIBABA, "default is cPanel’s selector too, so it is tried but names no provider.", "default", "default._domainkey TXT")),
  empty("alibaba-mail", "dkimTargets", none(ALIBABA, TXT_KEY)),
  empty("ovhcloud", "dkimSelectors", unused(OVH_DKIM, PER_CUSTOMER, "ovhmo3456789-selector1", '"selectorName": "ovhmo3456789-selector1"')),
  // providers.ts writes it as Hover's fixInclude, for a domain with Hover's MX and no SPF.
  empty("hover", "spfIncludes", unused(HOVER_SPF, "Every Tucows reseller gives this include, so it names no one; the check writes it only for a domain with Hover’s MX and no SPF.", "_spf.hostedemail.com", "Here is the most common SPF record used at Hover: v=spf1 include:_spf.hostedemail.com ~all")),
  empty("hover", "dkimSelectors", none(HOVER_SPF)),
  empty("hover", "dkimTargets", none(HOVER_SPF)),
  empty("vk-workspace", "dkimSelectors", none(VK_SPF)),
  empty("vk-workspace", "dkimTargets", none(VK_SPF)),
  empty("rackspace", "dkimSelectors", none(RACKSPACE)),
  empty("rackspace", "dkimTargets", none(RACKSPACE)),
  empty("salesforce", "mx", none(SALESFORCE_SPF)),
  empty("salesforce", "dkimSelectors", unused(SALESFORCE_DKIM, PER_CUSTOMER, "example-sf-a", "example-sf-a._domainkey.example.com.")),
  empty("aruba", "mx", none(ARUBA_SPF)),
  // “il selector utilizzato è a1”; tried, with Aruba as who uses it (otherSelectors).
  empty("aruba", "dkimSelectors", unused(ARUBA, "a1 is a short name other servers may use, so it is tried but names no provider.", "a1", "il selector utilizzato è a1")),
  empty("aruba", "dkimTargets", none(ARUBA)),
  // providers.ts writes it as Register.it and Nominalia's fixInclude, for a domain with its MX and
  // no SPF.
  empty("register-nominalia", "spfIncludes", unused(REGISTER_SPF, "A domain on Amen’s name servers gives this include too, as seen in DNS, so it names no one; the check writes it only for a domain with Register.it’s MX and no SPF.", "spf.webapps.net", 'VALORE SPF di Register Spa: "v=spf1 include:spf.webapps.net ~all"')),
  empty("register-nominalia", "dkimSelectors", unused(NOMINALIA, NOT_TRIED, "key-nomi001", "Nombre: key-nomi001._domainkey.midominio.com")),
  empty("infomaniak", "dkimSelectors", none(INFOMANIAK_SPF)),
  empty("infomaniak", "dkimTargets", none(INFOMANIAK_SPF)),
  empty("locaweb", "dkimSelectors", none(LOCAWEB)),
  empty("locaweb", "dkimTargets", none(LOCAWEB)),
  empty("transip", "dkimSelectors", unused(TRANSIP, NOT_TRIED, "transip-A", "Name: transip-A._domainkey")),
  empty("netcup", "mx", unused(NETCUP, "The page’s MX stands for the customer’s own mail server.", "mx1.netcup.net", "Destination: mx1.netcup.net ( mx1.netcup.net is to be replaced with the mail server address )")),
  empty("netcup", "dkimSelectors", unused(NETCUP, "key1 and key2 are tried on every check as Migadu’s, so a key there names no provider, not even through netcup’s CNAME target.", "key1", "Host: key1._domainkey Type: CNAME")),
  empty("all-inkl", "dkimSelectors", none(ALLINKL_SPF)),
  empty("all-inkl", "dkimTargets", none(ALLINKL_SPF)),
  empty("cyber-folks", "mx", none(CYBERFOLKS)),
  empty("cyber-folks", "dkimSelectors", unused(CYBERFOLKS, "x is DirectAdmin’s default selector too, so it is tried but names no provider.", "x", "selektora: w przypadku naszych serwerów jest to x")),
  empty("cyber-folks", "dkimTargets", none(CYBERFOLKS, TXT_KEY)),
  empty("godaddy", "dkimSelectors", unused(GODADDY_DKIM, NOT_TRIED, "secureserver1", "Nombre : Entrar secureserver1._domainkey .")),
  empty("godaddy", "dkimTargets", none(GODADDY_DKIM, "Each CNAME’s target is shown in the account; the page gives no common part.")),
  empty("arsys", "mx", unused(ARSYS_DNS, "Only an example in a general article on DNS, not a page of the mail’s values.", "mx.serviciodecorreo.es", "tudominio.com MX 10 mx.serviciodecorreo.es")),
  empty("arsys", "dkimSelectors", none(ARSYS_DMARC)),
  empty("arsys", "dkimTargets", none(ARSYS_DMARC)),
  empty("hostnet", "mx", unused(HOSTNET_WIX, "Only for its old platform; the page says the new one has another MX, shown in the account.", "mailfilter.hostnet.nl", "mailfilter.hostnet.nl Let op : Als je naar het nieuwe platform bent overgezet dan geldt er een ander MX-record.")),
  empty("hostnet", "dkimSelectors", none(HOSTNET_SPF)),
  empty("hostnet", "dkimTargets", none(HOSTNET_SPF)),
  empty("antagonist", "mx", none(ANTAGONIST, "The default MX points to mail. under the customer’s own domain.")),
  empty("antagonist", "dkimSelectors", unused(ANTAGONIST, NOT_TRIED, "whs1", "whs1._domainkey CNAME")),
  empty("namecheap-email-forwarding", "mx", none(NAMECHEAP_FORWARDING, "The MX records are set automatically; the page does not name them.")),
  empty("namecheap-email-forwarding", "dkimSelectors", none(NAMECHEAP_FORWARDING)),
  empty("namecheap-email-forwarding", "dkimTargets", none(NAMECHEAP_FORWARDING)),

  empty("mimecast", "dkimSelectors", none(MIMECAST_GATEWAY)),
  empty("mimecast", "dkimTargets", none(MIMECAST_GATEWAY)),
  empty("barracuda", "dkimSelectors", none(BARRACUDA_MX)),
  empty("barracuda", "dkimTargets", none(BARRACUDA_MX)),
  empty("hornetsecurity", "dkimSelectors", none(HORNETSECURITY)),
  empty("hornetsecurity", "dkimTargets", none(HORNETSECURITY)),
  empty("cisco-secure-email", "spfIncludes", none(CISCO)),
  empty("cisco-secure-email", "dkimSelectors", none(CISCO)),
  empty("cisco-secure-email", "dkimTargets", none(CISCO)),
  empty("marketo", "mx", none(MARKETO)),
  empty("marketo", "dkimSelectors", none(MARKETO)),
  empty("marketo", "dkimTargets", none(MARKETO)),
  empty("elastic-email", "mx", none(ELASTIC)),
  empty("elastic-email", "dkimSelectors", unused(ELASTIC, "The check does not try api; a key there is found when typed, and names no provider, as it has no CNAME target.", "api", "DKIM (TXT): Host/Name: api._domainkey.sub")),
  empty("elastic-email", "dkimTargets", none(ELASTIC, TXT_KEY)),
  empty("mailchannels", "mx", none(MAILCHANNELS)),
  empty("mailchannels", "dkimSelectors", none(MAILCHANNELS)),
  empty("mailchannels", "dkimTargets", none(MAILCHANNELS)),
  empty("activecampaign", "mx", none(ACTIVECAMPAIGN_SPF)),
  // acdkim1 is tried, with ActiveCampaign as who uses it (otherSelectors).
  empty("activecampaign", "dkimSelectors", unused(ACTIVECAMPAIGN, "Its page makes the include optional, so a list would ask about a key in use; acdkim1 is tried and names who uses it.", "acdkim1", "like acdkim1._domainkey (most common)")),
  empty("activecampaign", "dkimTargets", none(ACTIVECAMPAIGN)),
  empty("hostgator-brasil", "mx", none(HOSTGATOR, "The MX is mail. under the customer’s own domain.")),
  empty("hostgator-brasil", "spfIncludes", unused(HOSTGATOR, "HostGator in the US and Bluehost give this include too, so it names no one.", "websitewelcome.com", "seudominio.com.br TXT v=spf1 a mx include:websitewelcome.com ~ all")),
  empty("hostgator-brasil", "dkimSelectors", none(HOSTGATOR)),
  empty("hostgator-brasil", "dkimTargets", none(HOSTGATOR)),
  empty("hetzner", "spfIncludes", none(HETZNER)),
  empty("hetzner", "dkimSelectors", none(HETZNER)),
  empty("hetzner", "dkimTargets", none(HETZNER)),
  empty("host-europe", "mx", none(HOSTEUROPE)),
  empty("host-europe", "dkimSelectors", none(HOSTEUROPE)),
  empty("host-europe", "dkimTargets", none(HOSTEUROPE)),
  empty("o2switch", "mx", none(O2SWITCH)),
  empty("o2switch", "dkimSelectors", none(O2SWITCH)),
  empty("o2switch", "dkimTargets", none(O2SWITCH)),
  empty("kinghost", "mx", none(KINGHOST)),
  empty("kinghost", "dkimSelectors", none(KINGHOST)),
  empty("kinghost", "dkimTargets", unused(KINGHOST, "It names the domain that signs its customers’ mail, not a CNAME target of a key at their domain.", "dkim.kinghost.net", "Clientes : dkim.kinghost.net")),
  empty("mijndomein", "dkimSelectors", unused(MIJNDOMEIN, "The check does not try these selectors; a key there is found when typed, and names no provider, as its CNAME target is not one of Mijndomein’s own names.", "soverin1", "Type: CNAME Hostnaam: soverin1._domainkey Waarde: soverin1._domainkey.sover.in")),
  empty("mijndomein", "dkimTargets", unused(MIJNDOMEIN, "sover.in is not one of Mijndomein’s own names, so a key there is not credited to Mijndomein.", "sover.in", "Hostnaam: soverin1._domainkey Waarde: soverin1._domainkey.sover.in")),
];

/** These providers' flags, after those of index.ts. */
export const moreFlags: readonly FlagSource[] = [
  // Alone, these pages give redirect=, the record fixes.ts writes for a domain with their MX and no
  // SPF.
  { provider: "yandex-360", flag: "spfRedirect", ...YANDEX_SPF, quote: "Value : v=spf1 redirect=_spf.yandex.net" },
  { provider: "vk-workspace", flag: "spfRedirect", ...VK_SPF, quote: "Добавьте новую ТХТ-запись со следующим значением v=spf1 redirect=_spf.mail.ru" },
  // The record these pages give, a and mx before the include, is the one fixes.ts writes.
  { provider: "all-inkl", flag: "fixMechanisms", ...ALLINKL_SPF, quote: 'Example entry: yourdomain.com. IN TXT "v=spf1 a mx include:spf.kasserver.com ~all"' },
  { provider: "mijndomein", flag: "fixMechanisms", ...MIJNDOMEIN, quote: "Type: TXT Hostnaam: leeg laten Waarde: v=spf1 a mx include:spf.mijndomeinhosting.nl ~all" },
  { provider: "namecheap-email-forwarding", flag: "receiveOnly", ...NAMECHEAP_MX, quote: "Email Forwarding - if you wish to create personalized e-mail addresses for a domain and forward emails to other email accounts of your choice." },
];
