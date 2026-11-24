// The DKIM check (checkDkim) on providers that rotate their keys between selectors: an empty p= or
// a dangling CNAME in a slot not in use says nothing while another slot holds a live key.
import { describe, expect, it } from "vitest";
import { checkDkim } from "../src/checks/dkim.ts";
import { key, run } from "./helpers/dkim.ts";
import { fixtureResolver } from "./helpers/dns.ts";
import { ids } from "./helpers/findings.ts";
import { rsaKey } from "./helpers/keys.ts";
import type { Zone } from "./helpers/zone.ts";

// Microsoft 365 publishes selector1 and selector2; only the active one's target exists. Recorded
// on 2026-11-18: microsoft.com has selector2 live and selector1 dangling, github.com the opposite.
describe("Microsoft 365 rotation, recorded", () => {
  for (const [domain, live] of [
    ["microsoft.com", "selector2"],
    ["github.com", "selector1"],
  ] as const) {
    it(`${domain}: the dangling selector is not reported`, async () => {
      const r = await checkDkim({ resolver: fixtureResolver(undefined, "empty") }, domain);
      // The full-check recordings hold other selectors too; only the Microsoft pair matters here.
      // The 47 selectors the recordings lack answer empty.
      const pair = r.keys.filter((k) => k.selector === "selector1" || k.selector === "selector2");
      expect(pair.map((k) => k.selector)).toEqual([live]);
      expect(pair[0]?.bits).toBe(1024);
      expect(ids(r)).not.toContain("dkim-dangling-cname");
    });
  }

  it("a dangling selector1 with no live selector2 is reported", async () => {
    const r = await run({
      "selector1._domainkey.example.com": { CNAME: ["selector1-example-com._domainkey.example.onmicrosoft.example"] },
    });
    expect(ids(r)).toEqual(["dkim-dangling-cname", "dkim-not-found"]);
  });
});

describe("rotation groups", () => {
  const GROUPS: [string, string[], (s: string) => string][] = [
    ["Microsoft 365", ["selector1", "selector2"], (s) => `${s}-example-com._domainkey.example.onmicrosoft.com`],
    ["Hostinger", ["hostingermail-a", "hostingermail-b", "hostingermail-c"], (s) => `${s}.dkim.mail.hostinger.com`],
    ["Gandi", ["gm1", "gm2", "gm3"], (s) => `${s}.gandimail.net`],
    ["Purelymail", ["purelymail1", "purelymail2", "purelymail3"], (s) => `key${s.slice(-1)}.dkimroot.purelymail.com`],
    ["mailbox.org", ["mbo0001", "mbo0002", "mbo0003", "mbo0004"], (s) => `${s}._domainkey.mailbox.org`],
    ["Strato", ["strato-dkim-0002", "strato-dkim-0003"], (s) => `${s}._domainkey.rzone.de`],
    // One key shared by every customer, the other emptied (dkim1 had p= on 2026-11-19).
    ["MailPoet", ["mailpoet2", "mailpoet1"], (s) => `dkim${s.slice(-1)}.sendingservice.net`],
  ];
  for (const [name, [live = "", ...rest], target] of GROUPS) {
    it(`${name}: with ${live} live, an empty p= or a dangling CNAME in another slot says nothing`, async () => {
      const liveKey: Zone = {
        [`${live}._domainkey.example.com`]: { CNAME: [target(live)] },
        [target(live)]: { TXT: [`v=DKIM1; p=${rsaKey(2048)}`] },
      };
      const emptied: Zone = { ...liveKey };
      for (const s of rest)
        Object.assign(emptied, {
          [`${s}._domainkey.example.com`]: { CNAME: [target(s)] },
          [target(s)]: { TXT: ["v=DKIM1; p="] },
        });
      expect(ids(await run(emptied))).toEqual(["dkim-ok"]);
      const dangling: Zone = { ...liveKey };
      for (const s of rest) dangling[`${s}._domainkey.example.com`] = { CNAME: [target(s)] };
      expect(ids(await run(dangling))).toEqual(["dkim-ok"]);
      // With no live key in the group, both are still reported.
      const none: Zone = {};
      for (const s of [live, ...rest])
        Object.assign(none, {
          [`${s}._domainkey.example.com`]: { CNAME: [target(s)] },
          [target(s)]: { TXT: ["v=DKIM1; p="] },
        });
      expect(ids(await run(none))).toEqual(["dkim-revoked", "dkim-not-found"]);
    });
  }

  it("Hostinger with -a in TXT behind the CNAME and -b and -c empty gives no dkim-revoked", async () => {
    const r = await run({
      ...key("hostingermail-a", `v=DKIM1; p=${rsaKey(2048)}`),
      ...key("hostingermail-b", "v=DKIM1; p="),
      ...key("hostingermail-c", "v=DKIM1; p="),
    });
    expect(ids(r)).toEqual(["dkim-ok"]);
  });

  it("a revoked selector outside a group is still reported next to a live key", async () => {
    const r = await run({ ...key("gm1", `v=DKIM1; p=${rsaKey(2048)}`), ...key("zendesk1", "v=DKIM1; p=") });
    expect(ids(r)).toEqual(["dkim-revoked", "dkim-ok"]);
  });
});
