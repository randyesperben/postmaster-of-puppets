// The DKIM check over a zone (checkDkim), and a zone with a key record at a selector.
import { checkDkim } from "../../src/checks/dkim.ts";
import { type Zone, zoneResolver } from "./zone.ts";

export const run = (zone: Zone, extra: string[] = []) =>
  checkDkim({ resolver: zoneResolver(zone) }, "example.com", extra);
export const key = (selector: string, record: string | string[]): Zone => ({
  [`${selector}._domainkey.example.com`]: { TXT: [record] },
});
