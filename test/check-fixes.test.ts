// The SPF, MX, DKIM and no-mail fixes, through full checks: each fix, applied back to the zone,
// removes its finding and adds no critical or warning, and a finding the engine cannot fix gets
// none. The merge of two SPF records is in check-fixes-spf.test.ts, the DMARC fixes in
// check-fixes-dmarc.test.ts.
import { describe, expect, it } from "vitest";
import type { Finding, Report } from "../src/types.ts";
import { applyFix, bad, check, DKIM, googleZone, P4, SOA, stepThrough } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

describe("SPF, MX, DKIM and no-mail fixes", () => {
  it("+all in the domain's own record becomes ~all; terms after all go", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com +all ip4:192.0.32.9"];
    const r = await check(z);
    const f = r.findings.find((x) => x.fixes.length > 0 && x.group === "spf") as Finding;
    expect(f.fixes.map((x) => x.value)).toEqual(["v=spf1 include:_spf.google.com ~all"]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
    expect(after?.verdict).toBe("protected");
  });

  it("an open range in the domain's own record is dropped", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 ip4:0.0.0.0/0 include:_spf.google.com ~all"];
    const f = (await check(z)).findings.find((x) => x.id === "spf-open-range") as Finding;
    expect(f.fixes.map((x) => x.value)).toEqual(["v=spf1 include:_spf.google.com ~all"]);
  });

  it("an open term that is the only sender gets no fix: the record would authorize no one", async () => {
    for (const record of [
      "v=spf1 ip4:0.0.0.0/0 -all",
      "v=spf1 +all",
      "v=spf1 -ip4:192.0.2.1 ip6:::/0 ?all",
      "v=spf1 ~include:_spf.google.com +all",
    ]) {
      const z = googleZone();
      (z["example.com"] as Node).TXT = [record];
      const r = await check(z);
      expect(
        r.findings.filter((f) => f.group === "spf").flatMap((f) => f.fixes),
        record,
      ).toEqual([]);
      expect(ids(r), record).toEqual(expect.arrayContaining([expect.stringMatching(/^spf-(plus-all|open-range)$/)]));
    }
  });

  it("+all inside a provider's include gets no fix from the engine", async () => {
    const z = googleZone();
    (z["_spf.google.com"] as Node).TXT = ["v=spf1 +all"];
    const r = await check(z);
    expect(r.findings.filter((f) => f.group === "spf").flatMap((f) => f.fixes)).toEqual([]);
  });

  it("too many SPF lookups: no fix, the engine never removes an include", async () => {
    const z = googleZone();
    const inc = Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`);
    (z["example.com"] as Node).TXT = [`v=spf1 ${inc.join(" ")} ~all`];
    for (let i = 0; i < 11; i++) z[`s${i}.example.net`] = { TXT: ["v=spf1 -all"] };
    const r = await check(z);
    expect(ids(r)).toContain("spf-too-many-lookups");
    expect(r.findings.flatMap((f) => f.fixes)).toEqual([]);
  });

  it("no SPF on a Google Workspace domain: the provider's include with ~all", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = [];
    const f = (await check(z)).findings.find((x) => x.id === "spf-missing") as Finding;
    expect(f.fixes.map((x) => [x.host, x.value])).toEqual([["@", "v=spf1 include:_spf.google.com ~all"]]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });

  it("a null MX next to real hosts: remove the null MX", async () => {
    const z = googleZone();
    (z["example.com"] as Node).MX = ["0 .", "1 smtp.google.com"];
    const f = (await check(z)).findings.find((x) => x.id === "mx-null-with-others") as Finding;
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });

  it("a null MX with preference 10: set it to 0", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["10 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
    };
    const f = (await check(z)).findings.find((x) => x.id === "mx-null") as Finding;
    expect(f.fixes.map((x) => [x.action, x.type, x.value, x.replaces])).toEqual([["replace", "MX", "0 .", "10 ."]]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });

  it("a DKIM CNAME left by an old provider: remove it", async () => {
    const z = googleZone();
    z["s1._domainkey.example.com"] = { CNAME: ["s1.domainkey.u1.wl1.sendgrid.net"] };
    const f = (await check(z)).findings.find((x) => x.id === "dkim-dangling-cname") as Finding;
    expect(f.fixes.map((x) => [x.action, x.type, x.host])).toEqual([["remove", "CNAME", "s1._domainkey"]]);
    const [after] = await stepThrough(z, f);
    expect(ids(after as Report)).not.toContain("dkim-dangling-cname");
    expect(bad(after as Report)).toEqual([]);
  });

  it("a declared no-mail domain missing pieces gets the set at once", async () => {
    const z: Zone = { "example.com": { SOA, MX: ["0 ."] } };
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    let fixed = z;
    for (const f of r.findings) for (const fix of f.fixes) fixed = applyFix(fixed, fix);
    const after = await check(fixed);
    expect(after.verdict).toBe("protected");
    expect(bad(after)).toEqual([]);
    expect(r.findings.flatMap((f) => f.fixes.map((x) => x.value)).sort()).toEqual([
      "v=DKIM1; p=",
      "v=DMARC1; p=reject",
      "v=spf1 -all",
    ]);
  });

  it("probably no mail: two paths, the set with a null MX, or DMARC by steps", async () => {
    const z: Zone = { "example.com": { SOA, A: [P4] } };
    const r = await check(z);
    expect(r.mailUse).toBe("probably-none");
    const set = r.findings.find((f) => f.id === "mx-missing") as Finding;
    expect(set.fixes.map((x) => [x.type, x.host, x.value])).toEqual([
      ["MX", "@", "0 ."],
      ["TXT", "@", "v=spf1 -all"],
      ["TXT", "_dmarc", "v=DMARC1; p=reject"],
      ["TXT", "*._domainkey", "v=DKIM1; p="],
    ]);
    const steps = r.findings.find((f) => f.id === "dmarc-missing") as Finding;
    expect(steps.fixes.map((x) => x.step?.n)).toEqual([1, 2, 3]);
    const [after] = await stepThrough(z, set);
    expect(after?.mailUse).toBe("none-declared");
    expect(after?.verdict).toBe("protected");
    expect(bad(after as Report)).toEqual([]);
  });

  it("an SPF record published at example.com.example.com moves to the domain", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = [];
    z["example.com.example.com"] = { TXT: ["v=spf1 include:_spf.google.com ~all"] };
    const r = await check(z);
    const f = r.findings.find((x) => x.id === "record-name-doubled") as Finding;
    expect(f.fixes.map((x) => [x.action, x.name])).toEqual([
      ["remove", "example.com.example.com"],
      ["add", "example.com"],
    ]);
    expect(r.findings.find((x) => x.id === "spf-missing")?.fixes).toEqual([]);
    const [after] = await stepThrough(z, f);
    expect(bad(after as Report)).toEqual([]);
  });

  it("writes hosts relative to the zone of a subdomain", async () => {
    const z: Zone = {
      "example.com": { SOA, MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
      "mail.example.com": { MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
      "smtp.google.com": { A: [P4] },
      "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
      "google._domainkey.mail.example.com": { TXT: [DKIM] },
    };
    const r = await check(z, "mail.example.com");
    expect(r.zone).toBe("example.com");
    const step = r.findings.flatMap((f) => f.fixes).find((x) => x.name.startsWith("_dmarc"));
    expect([step?.host, step?.name]).toEqual(["_dmarc.mail", "_dmarc.mail.example.com"]);
  });
});
