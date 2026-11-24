// What every file of the provider sources builds its entries with (index.ts and more.ts): a page
// read on a day, the backing of a value, and why a list is empty. The types are
// index.ts's; this file holds no link.
import type { Backing, EmptyField, ProviderField, ValueSource } from "./index.ts";

export interface Page {
  url: string;
  read: string;
}
// The days the pages were read, each named and passed every time: a page added without being read
// cannot take a date by default.
export const READ_2026_11_20 = "2026-11-20";
export const READ_2026_11_24 = "2026-11-24";
export const page = (url: string, read: string): Page => ({ url, read });
export const vendor = (p: Page, quote: string): Backing => ({ basis: "vendor", url: p.url, read: p.read, quote });
export const dns = (read: string, ...seenOn: string[]): Backing => ({ basis: "dns", read, seenOn });

/** The source of one item of a provider's list. */
export const value = (provider: string, field: ProviderField, item: string, backing: Backing): ValueSource => ({
  provider,
  field,
  value: item,
  ...backing,
});
export type Why = Omit<EmptyField, "provider" | "field">;
export const none = (p: Page, note?: string): Why => ({
  reason: "none-documented",
  url: p.url,
  read: p.read,
  ...(note ? { note } : {}),
});
export const unused = (p: Page, note: string, documented: string, quote: string): Why => ({
  reason: "documented-not-used",
  url: p.url,
  read: p.read,
  note,
  documented,
  quote,
});
/** Why a provider's list is empty. */
export const empty = (provider: string, field: ProviderField, why: Why): EmptyField => ({ provider, field, ...why });
export const TXT_KEY = "The key is a TXT record, so there is no CNAME target.";
