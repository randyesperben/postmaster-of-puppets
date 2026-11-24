import { describe, expect, it } from "vitest";
import { checkSpf } from "../src/checks/spf.ts";
import { spfRecords } from "../src/checks/spf-terms.ts";
import type { SpfNode } from "../src/types.ts";
import { chunks } from "./helpers/dns.ts";
import { ids } from "./helpers/findings.ts";
import { includes, provider, run, spf } from "./helpers/spf.ts";
import { zoneResolver } from "./helpers/zone.ts";

describe("record selection (RFC 7208 §4.5)", () => {
  it("keeps only v=spf1 followed by a space or the end, in any case", () => {
    expect(spfRecords(["v=spf1 -all", "V=SPF1", "v=spf10 -all", "google-site-verification=x", "v=spf1"])).toEqual([
      "v=spf1 -all",
      "V=SPF1",
      "v=spf1",
    ]);
  });

  it("spf-missing when there is none", async () => {
    const r = await run({ "example.com": { TXT: ["google-site-verification=abc"] } });
    expect(ids(r)).toEqual(["spf-missing"]);
    expect(r.status).toBe("fail");
    expect(r.authorizes).toBe(false);
  });

  it("spf-multiple-records when there are two", async () => {
    const r = await run({
      "example.com": { TXT: ["v=spf1 include:_spf.google.com ~all", "v=spf1 include:sendgrid.net ~all"] },
    });
    expect(ids(r)).toEqual(["spf-multiple-records"]);
    expect(r.tree).toBeUndefined();
  });

  it("joins a record split over several strings without spaces (§3.3)", async () => {
    const r = await run({ "example.com": { TXT: [["v=spf1 include:_spf.exa", "mple.net -all"]] }, ...provider() });
    expect(r.record).toBe("v=spf1 include:_spf.example.net -all");
    expect(ids(r)).toEqual(["spf-ok"]);
  });
});

describe("one case per SPF finding", () => {
  it("spf-ok with an include and its tree", async () => {
    const r = await run(spf("v=spf1 include:_spf.example.net ~all", provider()));
    expect(ids(r)).toEqual(["spf-ok"]);
    expect(r.status).toBe("pass");
    expect(r.lookups).toBe(1);
    expect(r.includes).toEqual(["_spf.example.net"]);
    expect(r.authorizes).toBe(true);
    expect(r.tree?.children[0]).toMatchObject({
      term: "include:_spf.example.net",
      domain: "_spf.example.net",
      lookups: 1,
    });
    expect(r.tree?.children[0]?.children.map((c) => c.term)).toEqual(["ip4:192.0.2.0/24", "-all"]);
  });

  it("v=spf1 -all authorizes nobody", async () => {
    const r = await run(spf("v=spf1 -all"));
    expect(ids(r)).toEqual(["spf-ok"]);
    expect(r.authorizes).toBe(false);
  });

  for (const [record, why] of [
    ["v=spf1 ip4:192.0.2.300 -all", "bad IPv4"],
    ["v=spf1 ip4:192.0.2.1/33 -all", "IPv4 prefix"],
    ["v=spf1 ip6:2001:db8::/129 -all", "IPv6 prefix"],
    ["v=spf1 ip6:2001:db8:::1 -all", "bad IPv6"],
    ["v=spf1 include -all", "include without domain"],
    ["v=spf1 include:localhost -all", "domain without a dot"],
    ["v=spf1 incude:_spf.example.net -all", "unknown mechanism"],
    ["v=spf1 all:x", "all with a value"],
    ["v=spf1 exists:%{z}.example.net -all", "unknown macro"],
    ["v=spf1 exists:%{c}.example.net -all", "exp-only macro"],
    ["v=spf1 a:50% -all", "stray percent"],
    ["v=spf1 a/24/64 -all", "a with bad dual cidr"],
    ["v=spf1 ptr/24 -all", "ptr with a prefix"],
    ["v=spf1 ip4 -all", "ip4 without an address"],
    ["v=spf1 redirect=bad", "redirect to no domain"],
    ["v=spf1 a:example.com/033 -all", "leading zero prefix"],
    ["v=spf1 foo=a%b -all", "unknown modifier with a stray percent"],
    ["v=spf1 exists:%{d0}.example.net -all", "macro digit zero"],
    ["v=spf1 a:host.example- -all", "top label ending in a hyphen"],
    ["v=spf1 exists:%{i}.bad_ -all", "top label after a macro"],
    ["v=spf1 include:example.123 -all", "all-digit top label"],
  ] as const) {
    it(`spf-syntax-error: ${why}`, async () => {
      const r = await run(spf(record));
      expect(ids(r)).toContain("spf-syntax-error");
      expect(r.status).toBe("fail");
    });
  }

  for (const record of [
    "v=spf1 a:mail.example.com. -all",
    "v=spf1 exists:%{i}._spf.%{d} -all",
    "v=spf1 a:host.xn--p1ai -all",
    "v=spf1 a:host.12-3 -all",
    "v=spf1 exists:%{d01}.example.net -all",
  ]) {
    it(`valid syntax stays valid: ${record}`, async () => {
      expect(ids(await run(spf(record)))).not.toContain("spf-syntax-error");
    });
  }

  it("spf-syntax-error inside an include carries its path", async () => {
    const r = await run(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 ip4:300.0.0.1 -all")));
    const f = r.findings.find((x) => x.id === "spf-syntax-error");
    expect(f?.vars?.via).toBe("example.com > include:_spf.example.net");
  });

  it("pasted zone file quotes give spf-syntax-error with reason quotes", async () => {
    const r = await run(spf('v=spf1 include:_spf.example.net" "-all', provider()));
    const f = r.findings.find((x) => x.id === "spf-syntax-error");
    expect(f?.vars?.reason).toBe("quotes");
    expect(f?.found).toBe('include:_spf.example.net"');
    expect((await run(spf("v=spf1 foo:bar -all"))).findings[0]?.vars?.reason).toBe("unknown mechanism foo:bar");
  });

  it("spf-too-many-lookups: 11 includes, while 10 pass", async () => {
    const eleven = await run(includes(11));
    expect(ids(eleven)).toContain("spf-too-many-lookups");
    expect(eleven.lookups).toBe(11);
    const ten = await run(includes(10));
    expect(ids(ten)).toEqual(["spf-ok"]);
    expect(ten.lookups).toBe(10);
  });

  it("counts the cost of every branch, nested includes and a, mx, ptr and exists included", async () => {
    const r = await run(
      spf("v=spf1 a mx include:_spf.example.net exists:x.example.com -all", {
        ...provider("v=spf1 include:inner.example.net -all"),
        "inner.example.net": { TXT: ["v=spf1 a:host.example.org -all"] },
        "example.com": {
          TXT: ["v=spf1 a mx include:_spf.example.net exists:x.example.com -all"],
          A: ["192.0.2.1"],
          AAAA: ["2001:db8::1"],
          MX: ["10 mx.example.com"],
        },
        "host.example.org": { A: ["192.0.2.2"], AAAA: ["2001:db8::2"] },
        "x.example.com": { A: ["127.0.0.2"] },
      }),
    );
    const cost = (n: SpfNode | undefined): number => n?.lookups ?? -1;
    expect(r.tree?.children.map(cost)).toEqual([1, 1, 3, 1, 0]);
    expect(r.lookups).toBe(6);
    expect(r.voidLookups).toBe(0);
  });

  it("spf-too-many-void-lookups: three empty answers, while two pass", async () => {
    const three = await run(spf("v=spf1 a:v1.example.com a:v2.example.com mx:v3.example.com -all"));
    expect(ids(three)).toContain("spf-too-many-void-lookups");
    expect(three.voidLookups).toBe(3);
    const two = await run(spf("v=spf1 a:v1.example.com exists:v2.example.com -all"));
    expect(ids(two)).toEqual(["spf-ok"]);
    expect(two.voidLookups).toBe(2);
  });

  it("an a term with only AAAA is void for IPv4 senders (§5.3: one family per connection)", async () => {
    const r = await run(spf("v=spf1 a:v6.example.com -all", { "v6.example.com": { AAAA: ["2001:db8::1"] } }));
    expect(r.voidLookups).toBe(1);
  });

  it("spf-mx-too-many-hosts: an mx term with 11 MX records", async () => {
    const mx = Array.from({ length: 11 }, (_, i) => `${i} mx${i}.example.com`);
    const r = await run(spf("v=spf1 mx -all", { "example.com": { TXT: ["v=spf1 mx -all"], MX: mx } }));
    expect(ids(r)).toContain("spf-mx-too-many-hosts");
  });

  it("spf-include-no-spf: the included domain has no SPF record, and NXDOMAIN counts as void", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net include:gone.example.net -all", { "_spf.example.net": { TXT: ["hello"] } }),
    );
    expect(ids(r).filter((i) => i === "spf-include-no-spf")).toHaveLength(2);
    expect(r.voidLookups).toBe(1);
  });

  it("spf-multiple-records inside an include", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net -all", { "_spf.example.net": { TXT: ["v=spf1 -all", "v=spf1 ~all"] } }),
    );
    expect(r.findings.find((f) => f.id === "spf-multiple-records")?.vars?.via).toBe(
      "example.com > include:_spf.example.net",
    );
  });

  it("spf-redirect-no-spf", async () => {
    const r = await run(spf("v=spf1 redirect=_spf.example.net"));
    expect(ids(r)).toContain("spf-redirect-no-spf");
  });

  it("follows redirect as the domain's own policy, and ignores it next to all (§6.1)", async () => {
    const followed = await run(spf("v=spf1 redirect=_spf.example.net", provider("v=spf1 ip4:192.0.2.0/24 ?all")));
    expect(ids(followed)).toEqual(["spf-neutral-all", "spf-ok"]);
    expect(followed.lookups).toBe(1);
    const ignored = await run(spf("v=spf1 -all redirect=_spf.example.net"));
    expect(ids(ignored)).toEqual(["spf-ok"]);
    expect(ignored.lookups).toBe(0);
  });

  it("spf-duplicate-modifier", async () => {
    const r = await run(
      spf("v=spf1 redirect=a.example.net redirect=b.example.net", {
        "a.example.net": { TXT: ["v=spf1 -all"] },
        "b.example.net": { TXT: ["v=spf1 -all"] },
      }),
    );
    expect(ids(r)).toContain("spf-duplicate-modifier");
    const exp = await run(spf("v=spf1 -all exp=a.example.net exp=b.example.net"));
    expect(ids(exp)).toContain("spf-duplicate-modifier");
  });

  it("spf-plus-all in the domain's own record, written as +all or bare all", async () => {
    for (const rec of ["v=spf1 +all", "v=spf1 all"]) {
      const r = await run(spf(rec));
      expect(ids(r)).toEqual(["spf-plus-all"]);
      expect(r.findings[0]?.vars?.via).toBe("example.com");
      expect(r.status).toBe("fail");
    }
  });

  it("spf-plus-all through an include that returns +all", async () => {
    const r = await run(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 +all")));
    expect(r.findings.find((f) => f.id === "spf-plus-all")?.vars?.via).toBe("example.com > include:_spf.example.net");
  });

  it("a ~all or -all inside an include opens nothing", async () => {
    const r = await run(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 ip4:192.0.2.0/24 ~all")));
    expect(ids(r)).toEqual(["spf-ok"]);
  });

  it("spf-open-range: ip4:0.0.0.0/0 and ip6:::/0, also inside an include", async () => {
    expect(ids(await run(spf("v=spf1 ip4:0.0.0.0/0 -all")))).toEqual(["spf-open-range"]);
    expect(ids(await run(spf("v=spf1 ip6:::/0 -all")))).toEqual(["spf-open-range"]);
    const nested = await run(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 ip4:192.0.2.1/0 -all")));
    expect(ids(nested)).toEqual(["spf-open-range"]);
    expect(nested.findings[0]?.vars?.via).toBe("example.com > include:_spf.example.net");
    expect(ids(await run(spf("v=spf1 -ip4:0.0.0.0/0 ~all")))).toEqual(["spf-ok"]);
  });

  it("spf-wide-range in the domain's own record only, and only for pass", async () => {
    expect(ids(await run(spf("v=spf1 ip4:198.51.0.0/15 -all")))).toEqual(["spf-wide-range"]);
    expect(ids(await run(spf("v=spf1 ip6:2001:db8::/31 -all")))).toEqual(["spf-wide-range"]);
    expect(ids(await run(spf("v=spf1 ip4:198.51.0.0/16 ip6:2001:db8::/32 -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(spf("v=spf1 ~ip4:10.0.0.0/8 -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 ip4:10.0.0.0/8 -all"))))).toEqual(
      ["spf-ok"],
    );
  });

  it("spf-neutral-all: ?all, or no all and no redirect", async () => {
    expect(ids(await run(spf("v=spf1 ip4:192.0.2.1 ?all")))).toEqual(["spf-neutral-all", "spf-ok"]);
    expect(ids(await run(spf("v=spf1 ip4:192.0.2.1")))).toEqual(["spf-neutral-all", "spf-ok"]);
  });

  it("spf-ptr", async () => {
    const r = await run(spf("v=spf1 ptr -all"));
    expect(ids(r)).toEqual(["spf-ptr"]);
    expect(r.lookups).toBe(1);
    expect(r.status).toBe("weak");
  });

  it("spf-terms-after-all", async () => {
    expect(ids(await run(spf("v=spf1 -all ip4:192.0.2.1")))).toEqual(["spf-terms-after-all", "spf-ok"]);
  });

  it("spf-too-large: a record over 450 octets, split over several strings", async () => {
    const ips = Array.from({ length: 40 }, (_, i) => `ip4:192.0.2.${i}`).join(" ");
    const record = `v=spf1 ${ips} -all`;
    expect(record.length).toBeGreaterThan(450);
    const r = await run({ "example.com": { TXT: [chunks(record)] } });
    expect(r.record).toBe(record);
    expect(ids(r)).toEqual(["spf-too-large"]);
  });

  it("the size counts the name and every TXT string at it (§3.4)", async () => {
    const ips = Array.from({ length: 20 }, (_, i) => `ip4:192.0.2.${i}`).join(" ");
    const record = `v=spf1 ${ips} -all`;
    const other = `google-site-verification=${"x".repeat(200)}`;
    const big = await run({ "example.com": { TXT: [record, chunks(other)] } });
    expect(ids(big)).toEqual(["spf-too-large"]);
    // The SPF record alone stays under 450, so the found line names both parts.
    expect(big.findings[0]?.found).toBe(
      `${"example.com".length + record.length + other.length} octets in 2 TXT records; the SPF record is ${record.length}`,
    );
    // 449 octets fit; 450 do not (§3.4: under 450).
    const pad = (n: number) => `v=spf1 ip4:192.0.2.1 -all note=${"e".repeat(n)}`;
    const base = "example.com".length + pad(0).length;
    expect(ids(await run({ "example.com": { TXT: [chunks(pad(449 - base))] } }))).toEqual(["spf-ok"]);
    expect(ids(await run({ "example.com": { TXT: [chunks(pad(450 - base))] } }))).toEqual(["spf-too-large"]);
  });

  // A short SPF record next to old verification records can still make the answer large. §3.4
  // counts every TXT record at the name, so the finding stays; the var others tells which record
  // to shorten.
  it("a short SPF record among large TXT records carries others, and the SPF size", async () => {
    const record = "v=spf1 include:_spf.example.net -all";
    const verifications = Array.from({ length: 6 }, (_, i) => `site-verification-${i}=${"v".repeat(60)}`);
    const r = await run({ "example.com": { TXT: [record, ...verifications] }, ...provider() });
    expect(ids(r)).toEqual(["spf-too-large"]);
    const f = r.findings[0];
    const size = "example.com".length + record.length + verifications.reduce((n, v) => n + v.length, 0);
    expect(f?.vars).toEqual({ others: 6 });
    expect(f?.found).toBe(`${size} octets in 7 TXT records; the SPF record is ${record.length}`);
  });

  it("an SPF record that is large on its own carries no others", async () => {
    const ips = Array.from({ length: 40 }, (_, i) => `ip4:192.0.2.${i}`).join(" ");
    const record = `v=spf1 ${ips} -all`;
    const r = await run({ "example.com": { TXT: [chunks(record), "site-verification=abc"] } });
    expect(ids(r)).toEqual(["spf-too-large"]);
    expect(r.findings[0]?.vars).toBeUndefined();
    expect(r.findings[0]?.found).toBe(
      `${"example.com".length + record.length + "site-verification=abc".length} octets`,
    );
  });

  it("spf-sender-macros: counted as a lookup, never queried", async () => {
    const zone = spf("v=spf1 exists:%{i}._spf.%{d} -all");
    const resolver = zoneResolver(zone);
    const r = await checkSpf({ resolver }, "example.com");
    expect(ids(r)).toEqual(["spf-sender-macros", "spf-ok"]);
    expect(r.lookups).toBe(1);
    expect(resolver.asked).toEqual(["example.com TXT"]);
  });

  it("expands %{d} with its transformers", async () => {
    // -exists: with only %{d}, a name that resolves matches every address, so + would open the
    // domain.
    const zone = spf("v=spf1 include:_spf.%{d} a:%{d2}.example.org -exists:%{dr}.x.example.net -all", {
      "_spf.example.com": { TXT: ["v=spf1 -all"] },
      "example.com.example.org": { A: ["192.0.2.1"] },
      "com.example.x.example.net": { A: ["127.0.0.1"] },
    });
    const resolver = zoneResolver(zone);
    const r = await checkSpf({ resolver }, "example.com");
    expect(ids(r)).toEqual(["spf-ok"]);
    expect(resolver.asked).toContain("_spf.example.com TXT");
    expect(resolver.asked).toContain("example.com.example.org A");
    expect(resolver.asked).toContain("com.example.x.example.net A");
  });
});
