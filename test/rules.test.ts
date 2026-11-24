// rules.ts: the verdict and delivery tables as data. verdict.test.ts tests the decisions they
// drive.
import { describe, expect, it } from "vitest";
import { deliveryRules, verdictRules } from "../src/rules.ts";

describe("rules", () => {
  it("transcribes the verdict table in order, ending in protected", () => {
    expect(verdictRules.map((r) => r.result)).toEqual([
      "cant-tell",
      "spoofable",
      "spoofable",
      "partly-protected",
      "protected",
    ]);
  });

  it("transcribes the delivery table in order", () => {
    expect(deliveryRules.map((r) => r.result)).toEqual([
      "no-mail",
      "at-risk",
      "at-risk",
      "at-risk",
      "at-risk",
      "at-risk",
      "unknown",
      "ok",
    ]);
  });

  // Delivery: no-mail is a null MX with no sending signals (an SPF that authorizes someone or a
  // usable DKIM key); with them the domain is at-risk (RFC 7505 §4.2).
  it("says no-mail needs a null MX and no sending signals", () => {
    const noMail = deliveryRules.find((r) => r.result === "no-mail")?.when ?? "";
    expect(noMail).toMatch(/null MX/);
    expect(noMail).toMatch(/SPF/);
    expect(noMail).toMatch(/DKIM/);
  });

  it("cites an https source for every rule", () => {
    for (const r of [...verdictRules, ...deliveryRules]) {
      expect(r.when.length).toBeGreaterThan(20);
      expect(r.source.url).toMatch(/^https:\/\//);
    }
  });
});
