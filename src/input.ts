// The text a caller passes, turned into the domain to check: a domain, a web address or an email
// address all work. Also the rule for a DKIM selector given with it.
import { MAX_LABEL, MAX_NAME } from "./dns/names.ts";
import type { ParsedInput } from "./types.ts";

// UTS #46 maps these to a full stop, so the URL parser reads them as label separators.
const DOT = "[.\u3002\uFF0E\uFF61]";
// The end of the host: WHATWG URL treats a backslash as a slash in http and https.
const HOST_END = /[/?#\\]/;

/**
 * Finds the domain to check in what someone typed or pasted: a domain, a web address, an email
 * address or a From line. Unicode names come back in ASCII (punycode) as `domain`, and a leading
 * www. is dropped. Never throws: text with no domain in it gives `ok: false` and the reason.
 */
export function parseInput(raw: string): ParsedInput {
  let s = raw.trim();
  if (s === "") return { ok: false, error: "empty" };
  let note: "www-removed" | "from-email" | "from-url" | undefined;
  // A pasted From line: Ana <ana@example.com>.
  const angle = /<([^<>]*)>$/.exec(s);
  if (angle) s = (angle[1] ?? "").trim();

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    note = "from-url";
  }
  s = s.replace(/^mailto:/i, "");
  // The part after the last @ of an address, or of the user:password@ in a URL.
  const at = s.split(HOST_END)[0]?.lastIndexOf("@") ?? -1;
  if (at >= 0) {
    s = s.slice(at + 1);
    note ??= "from-email";
  }
  // IPv6 literals, bare or in brackets: a host with a port has one colon at most.
  const hostPort = s.split(HOST_END)[0] ?? "";
  if (hostPort.startsWith("[") || (hostPort.match(/:/g) ?? []).length >= 2) return { ok: false, error: "ip-address" };
  // Path, query, fragment and port: whatever follows the host.
  const host = hostPort.split(":")[0] ?? "";
  if (host !== s) note ??= "from-url";

  let display = host.toLowerCase().replace(new RegExp(`${DOT}$`), "");
  if (display === "" || /\s/.test(display)) return { ok: false, error: "not-a-domain" };
  // The name shown must be the name checked: no ASCII the URL parser would drop, decode or
  // read as something else (%41, quotes, =). Non-ASCII letters go through IDNA below.
  if ([...display].some((c) => c < "\x80" && !/[a-z0-9._-]/.test(c))) return { ok: false, error: "not-a-domain" };
  // A pasted DMARC or DKIM record name: check the domain it belongs to.
  display = display.replace(new RegExp(`^(_dmarc|[^.\u3002\uFF0E\uFF61]+${DOT}_domainkey)${DOT}`), "");

  // The runtime's WHATWG URL parser applies IDNA (UTS #46): münchen.de becomes xn--mnchen-3ya.de.
  let domain: string;
  try {
    domain = new URL(`http://${display}/`).hostname;
  } catch {
    return { ok: false, error: "not-a-domain" };
  }
  if (domain.startsWith("www.") && domain.split(".").length > 2) {
    domain = domain.slice(4);
    display = display.replace(new RegExp(`^[^.\u3002\uFF0E\uFF61]*${DOT}`), "");
    note = "www-removed";
  }
  const labels = domain.split(".");
  const last = labels[labels.length - 1] ?? "";
  // A name that ends in a number is an IPv4 address to the URL parser: 1.2.3.4, 0x7f.1, 3232235777.
  if (/^(0x[0-9a-f]*|\d+)$/i.test(last)) return { ok: false, error: "ip-address" };
  if (labels.length < 2) return { ok: false, error: "not-a-domain" };
  if (domain.length > MAX_NAME || labels.some((l) => l.length > MAX_LABEL)) return { ok: false, error: "too-long" };
  if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(l))) return { ok: false, error: "not-a-domain" };

  const out: ParsedInput = { ok: true, domain, display };
  if (note) out.note = note;
  return out;
}

/**
 * A selector is a dot-separated list of labels (RFC 6376 §3.1), and the name asked must fit in
 * 255 octets on the wire, 253 as text (RFC 1035 §2.3.4). Domains reach here in ASCII (punycode).
 * One rule for every caller that takes a selector.
 */
export function validSelector(s: string, domain: string): boolean {
  return (
    /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$/i.test(s) &&
    `${s}._domainkey.${domain}`.length <= MAX_NAME
  );
}
