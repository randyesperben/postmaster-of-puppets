// The DMARC check over a zone (checkDmarc), and a zone with one DMARC record.
import { checkDmarc } from "../../src/checks/dmarc.ts";
import type { NameExists } from "../../src/types.ts";
import { type Zone, zoneResolver } from "./zone.ts";

export const run = (zone: Zone, domain = "example.com", exists?: NameExists) =>
  checkDmarc({ resolver: zoneResolver(zone) }, domain, exists === undefined ? {} : { exists });
export const dmarc = (record: string, extra: Zone = {}, at = "example.com"): Zone => ({
  [`_dmarc.${at}`]: { TXT: [record] },
  ...extra,
});
