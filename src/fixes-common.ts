// What the builders of fixes share (fixes.ts, fixes-dmarc.ts): a fix before its host is set, the
// first finding of a list that is present, and the no-mail records: the null MX, SPF -all,
// DMARC p=reject and empty DKIM key a domain without mail publishes.
import type { Finding, FindingId, Fix, Report } from "./types.ts";

export const NO_MAIL_SPF = "v=spf1 -all";
export const NO_MAIL_DMARC = "v=DMARC1; p=reject";
export const NO_MAIL_DKIM = "v=DKIM1; p=";

export type FixDraft = Omit<Fix, "host">;

export function first(r: Report, ids: readonly FindingId[]): Finding | undefined {
  for (const id of ids) {
    const f = r.findings.find((x) => x.id === id);
    if (f) return f;
  }
  return undefined;
}
