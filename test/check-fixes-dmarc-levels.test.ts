// The DMARC chain never asks less than the current record, and never jumps: records that RFC 7489
// reads differently from RFC 9989 (a tag name in capitals, V=DMARC1, a repeated tag), a policy
// value in capitals, an inherited pct=0, and a pct that lowers nothing. Each record's chain is
// applied step by step; after each step neither reading (simulation.asks, and sampled.full where
// pct splits them) is lower than before, and the chain has the steps it should.
import { describe, expect, it } from "vitest";
import type { Finding } from "../src/types.ts";
import { check, expectNoStepLowers, googleZone, inheritingShop, RUA, stepThrough } from "./helpers/check.ts";
import type { Zone } from "./helpers/zone.ts";

const R = `rua=mailto:${RUA}`;

/** The chain's values, after checking that no step lowers either reading. */
async function chain(zone: Zone, domain = "example.com"): Promise<string[]> {
  const r = await check(zone, domain);
  const f = r.findings.find((x) => x.group === "dmarc" && x.fixes.some((y) => y.name.startsWith("_dmarc."))) as
    Finding | undefined;
  if (!f) return [];
  expectNoStepLowers(r, await stepThrough(zone, f, domain));
  return f.fixes.filter((x) => x.action !== "remove").map((x) => x.value);
}

const Q = `v=DMARC1; p=quarantine; ${R}`;
const REJ = `v=DMARC1; p=reject; ${R}`;

describe("the DMARC chain: no step asks less, none jumps", () => {
  // The step equal to the current record goes only when both readings read it alike.
  it.each([
    [`v=DMARC1; p=quarantine; PCT=25; ${R}`],
    [`v=DMARC1;p=quarantine;Pct=25;${R}`],
    [`v=DMARC1; p=quarantine; PCT=0; ${R}`],
    [`v=DMARC1; p=quarantine; SP=none; ${R}`],
    [`V=DMARC1; p=quarantine; ${R}`],
    [`V=DMARC1;p=quarantine;${R}`],
    [`v=DMARC1; p=quarantine; p=quarantine; ${R}`],
  ])("%s: a tag RFC 7489 reads otherwise keeps its step to quarantine", async (record) => {
    expect(await chain(googleZone(record))).toEqual([Q, REJ]);
  });

  it("a tag neither reading reads (foo=bar) is the current record: one fix, to reject", async () => {
    expect(await chain(googleZone(`v=DMARC1;p=quarantine;foo=bar;${R}`))).toEqual([REJ]);
  });

  // A policy value in capitals is read as the engine reads it.
  it.each([
    [`v=DMARC1; p=QUARANTINE; ${R}`, [REJ]],
    [`v=DMARC1;p=Quarantine;${R}`, [REJ]],
    [`v=DMARC1; p=QUARANTINE; pct=25; ${R}`, [Q, REJ]],
    [`v=DMARC1; p=REJECT; pct=50; ${R}`, [REJ]],
    [`v=DMARC1; p=reject; sp=NONE; ${R}`, [`v=DMARC1; p=reject; sp=quarantine; ${R}`, REJ]],
  ])("%s: the policy in capitals is that policy", async (record, values) => {
    expect(await chain(googleZone(record))).toEqual(values);
  });

  // A parent's record that lowers both readings (pct=0, t=y with pct=0) is not the current level.
  it.each([
    [`v=DMARC1; p=reject; pct=0; ${R}`, [REJ]],
    [`v=DMARC1; p=quarantine; pct=0; ${R}`, [Q, REJ]],
    [`v=DMARC1; p=quarantine; pct=0; t=y; ${R}`, [Q, REJ]],
  ])(
    "inherited %s: the steps on the name's own record start from the level the parent publishes",
    async (parent, values) => {
      expect(await chain(inheritingShop(parent), "shop.example.com")).toEqual(values);
    },
  );

  // A pct that lowers nothing is no step.
  it.each([
    `v=DMARC1; p=quarantine; pct=100; ${R}`,
    `v=DMARC1; p=quarantine; pct=; ${R}`,
    `v=DMARC1; p=quarantine; pct=abc; ${R}`,
  ])("%s: one fix, to reject", async (record) => {
    expect(await chain(googleZone(record))).toEqual([REJ]);
  });

  // pct=0 like pct 1 to 99, no t=y step.
  it.each([
    [`v=DMARC1; p=quarantine; pct=0; ${R}`, [Q, REJ]],
    [`v=DMARC1; p=reject; pct=0; ${R}`, [REJ]],
    [`v=DMARC1; p=reject; sp=none; pct=0; ${R}`, [`v=DMARC1; p=reject; sp=quarantine; ${R}`, REJ]],
  ])("%s: no t=y", async (record, values) => {
    expect(await chain(googleZone(record))).toEqual(values);
  });
});
