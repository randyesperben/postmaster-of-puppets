// The sources the catalog's entries cite (catalog/), which the verdict's rules share
// (rules.ts). Every source of the catalog was read on rfc-editor.org (or support.google.com) on
// 2026-11-18; the anchors use the .html form, which answers 200 without a redirect.

import type { Source } from "../types.ts";

/** An RFC section as a source, linked to its anchor on rfc-editor.org. */
export function rfc(n: number, section: string): Source {
  return {
    label: `RFC ${n} §${section}`,
    url: `https://www.rfc-editor.org/rfc/rfc${n}.html#section-${section}`,
  };
}

/** Google's guidelines for senders, which the catalog and the delivery rules cite. */
export const GOOGLE_SENDERS: Source = {
  label: "Google, Email sender guidelines",
  url: "https://support.google.com/mail/answer/81126",
};
