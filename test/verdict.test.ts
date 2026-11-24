import { describe, expect, it } from "vitest";
import { finding } from "../src/findings.ts";
import { deliveryRules, verdictRules } from "../src/rules.ts";
import type { FindingId, Group } from "../src/types.ts";
import { decideDelivery, decideMailUse, decideVerdict, type Facts, spfLookupDecides } from "../src/verdict.ts";

// A domain with mail that is fully fine: Protected, delivery ok. Each test changes one thing.
function facts(change: (f: Facts) => void = () => {}): Facts {
  const f: Facts = {
    partial: false,
    findings: [],
    mx: { lookup: "ok", nullMx: false, hosts: 1, usable: 1, unknown: false },
    spf: { authorizes: true },
    dmarc: { failed: false, effective: "reject", subdomainsOpen: false },
    dkim: { found: true, usable: true, failed: false },
  };
  change(f);
  return f;
}
const withFinding = (id: FindingId, group?: Group, vars?: Record<string, string>) => (f: Facts) => {
  const extra: { group?: Group; vars?: Record<string, string> } = {};
  if (group) extra.group = group;
  if (vars) extra.vars = vars;
  f.findings = [...f.findings, finding(id, extra)];
};
const nullNoSending = (f: Facts) => {
  f.mx = { lookup: "ok", nullMx: true, hosts: 0, usable: 0, unknown: false };
  f.spf.authorizes = false;
  f.dkim = { found: false, usable: false, failed: false };
};
/** The decision with its cause as the finding's id, the way a row is read. */
const delivery = (f: Facts) => {
  const { cause, ...d } = decideDelivery(f, decideMailUse(f));
  return cause ? { ...d, cause: cause.id } : d;
};

describe("verdict rules, one test per row of rules.ts", () => {
  it("row 0, Can't tell: DMARC unanswered, SPF unanswered under quarantine or reject, or DNSSEC broken", () => {
    const cases: Facts[] = [
      facts((f) => ((f.partial = true), withFinding("lookup-failed", "spf")(f))),
      facts((f) => (f.dmarc.failed = true)),
      facts((f) => ((f.dmarc.failed = true), (f.dmarc.effective = undefined))),
      facts((f) => ((f.dmarc.effective = "quarantine"), withFinding("lookup-failed", "spf")(f))),
      facts(withFinding("lookup-failed", "spf")),
      facts(withFinding("dnssec-broken", "spf")),
      facts(withFinding("dnssec-broken", "dmarc")),
    ];
    for (const c of cases) expect(decideVerdict(c)).toEqual({ result: "cant-tell", rule: 0 });
    expect(verdictRules[0]?.result).toBe("cant-tell");
  });

  it("row 0 wins over everything below it: never Protected with data missing", () => {
    expect(decideVerdict(facts((f) => ((f.dmarc.failed = true), (f.dmarc.effective = "reject")))).result).toBe(
      "cant-tell",
    );
    expect(
      decideVerdict(facts((f) => (withFinding("lookup-failed", "spf")(f), withFinding("spf-plus-all")(f)))).result,
    ).toBe("cant-tell");
  });

  // The domain's own SPF, answered in full, already lets anyone send, so any DMARC answer gives
  // Spoofable (row 1 or row 2): DMARC that did not answer changes nothing. An opening in the
  // organizational domain's SPF counts only with relaxed SPF alignment, which DMARC says: there
  // DMARC still counts.
  it("DMARC unanswered with the domain's own SPF open and answered in full: Spoofable by row 2", () => {
    const unanswered: ((f: Facts) => void)[] = [
      (f) => ((f.dmarc.failed = true), (f.dmarc.effective = undefined)),
      (f) => (f.dmarc.failed = true),
      withFinding("dnssec-broken", "dmarc"),
    ];
    for (const open of ["spf-plus-all", "spf-open-range"] as const) {
      for (const dmarc of unanswered) {
        expect(decideVerdict(facts((f) => (dmarc(f), withFinding(open, "spf")(f))))).toEqual({
          result: "spoofable",
          rule: 2,
        });
        // An unanswered SPF lookup may stop receivers before the opening (temperror, RFC 7208
        // §4.4).
        expect(
          decideVerdict(facts((f) => (dmarc(f), withFinding(open, "spf")(f), withFinding("lookup-failed", "spf")(f)))),
        ).toEqual({ result: "cant-tell", rule: 0 });
        expect(
          decideVerdict(facts((f) => (dmarc(f), withFinding(open, "spf")(f), withFinding("dnssec-broken", "spf")(f)))),
        ).toEqual({ result: "cant-tell", rule: 0 });
        expect(decideVerdict(facts((f) => (dmarc(f), withFinding(open, "spf", { org: "example.com" })(f))))).toEqual({
          result: "cant-tell",
          rule: 0,
        });
      }
    }
  });

  // The time limit counts through the lookups it cut (lookup-failed in DMARC or SPF): alone, with
  // DKIM, MTA-STS or a rua authorization left unanswered, it changes no row.
  it("the time limit alone leaves the verdict to the rows that read DMARC and SPF", () => {
    expect(decideVerdict(facts((f) => (f.partial = true)))).toEqual({ result: "protected", rule: 4 });
    expect(decideVerdict(facts((f) => ((f.partial = true), (f.dmarc.effective = "quarantine"))))).toEqual({
      result: "partly-protected",
      rule: 3,
    });
    expect(decideVerdict(facts((f) => ((f.partial = true), withFinding("lookup-failed", "dkim")(f))))).toEqual({
      result: "protected",
      rule: 4,
    });
  });

  it("only what can change the verdict leaves it at Can't tell: SPF with no DMARC or none, and MX never", () => {
    // With DMARC confirmed missing or at none the domain is Spoofable whatever SPF says.
    for (const effective of [undefined, "none"] as const) {
      const set = (f: Facts) => (f.dmarc.effective = effective);
      expect(decideVerdict(facts((f) => (set(f), withFinding("lookup-failed", "spf")(f))))).toEqual({
        result: "spoofable",
        rule: 1,
      });
      expect(decideVerdict(facts((f) => (set(f), withFinding("dnssec-broken", "spf")(f))))).toEqual({
        result: "spoofable",
        rule: 1,
      });
      expect(decideVerdict(facts((f) => (set(f), (f.partial = true))))).toEqual({ result: "spoofable", rule: 1 });
    }
    // No row of the verdict reads MX (RFC 9989 §4.10 finds the policy without it).
    expect(decideVerdict(facts((f) => (f.mx.lookup = "failed")))).toEqual({ result: "protected", rule: 4 });
    expect(decideVerdict(facts((f) => (f.mx.lookup = "dnssec-broken")))).toEqual({ result: "protected", rule: 4 });
    expect(decideVerdict(facts((f) => ((f.mx.lookup = "failed"), (f.dmarc.effective = "none"))))).toEqual({
      result: "spoofable",
      rule: 1,
    });
  });

  it("a lookup failed elsewhere (DKIM, transport, an MX host) does not hide the verdict", () => {
    expect(decideVerdict(facts(withFinding("lookup-failed", "dkim"))).result).toBe("protected");
    expect(decideVerdict(facts(withFinding("lookup-failed", "mx"))).result).toBe("protected");
  });

  it("row 1, Spoofable: no DMARC applies, or the effective policy is none", () => {
    expect(decideVerdict(facts((f) => (f.dmarc.effective = undefined)))).toEqual({ result: "spoofable", rule: 1 });
    expect(decideVerdict(facts((f) => (f.dmarc.effective = "none")))).toEqual({ result: "spoofable", rule: 1 });
  });

  it("row 2, Spoofable: SPF open to the whole internet, even with DMARC at reject (case F of check.test.ts)", () => {
    expect(decideVerdict(facts(withFinding("spf-plus-all")))).toEqual({ result: "spoofable", rule: 2 });
    expect(decideVerdict(facts(withFinding("spf-open-range")))).toEqual({ result: "spoofable", rule: 2 });
  });

  it("row 3, Partly protected: quarantine, or reject with subdomains open", () => {
    expect(decideVerdict(facts((f) => (f.dmarc.effective = "quarantine")))).toEqual({
      result: "partly-protected",
      rule: 3,
    });
    expect(decideVerdict(facts((f) => (f.dmarc.subdomainsOpen = true)))).toEqual({
      result: "partly-protected",
      rule: 3,
    });
  });

  it("row 4, Protected: reject and no subdomain at none", () => {
    expect(decideVerdict(facts())).toEqual({ result: "protected", rule: 4 });
  });

  // The Can't tell lines name only the SPF lookups the verdict counts.
  // SPF here is the domain's own record.
  it("an SPF lookup past the opening term or at the Organizational Domain counts only while SPF is closed", () => {
    const failed = (vars: Record<string, string | number> = {}) =>
      finding("lookup-failed", { group: "spf", found: "x TXT", vars });
    const [reached, past, org] = [failed(), failed({ unreached: 1 }), failed({ org: "example.com" })];
    const open = finding("spf-open-range", { found: "ip4:0.0.0.0/0" });
    expect([reached, past, org].map((x) => spfLookupDecides([open, reached, past, org], x))).toEqual([
      true,
      false,
      false,
    ]);
    expect([reached, past, org].map((x) => spfLookupDecides([reached, past, org], x))).toEqual([true, true, true]);
    // The Organizational Domain's own opening is no opening of the domain's.
    const orgOpen = finding("spf-plus-all", { found: "+all", vars: { org: "example.com" } });
    expect(spfLookupDecides([orgOpen, past], past)).toBe(true);
  });

  it("returns rule indexes that match the order of verdictRules", () => {
    const seen = [
      decideVerdict(facts((f) => (f.partial = true))),
      decideVerdict(facts((f) => (f.dmarc.effective = "none"))),
      decideVerdict(facts(withFinding("spf-plus-all"))),
      decideVerdict(facts((f) => (f.dmarc.effective = "quarantine"))),
      decideVerdict(facts()),
    ];
    expect(seen.map((d) => verdictRules[d.rule]?.result)).toEqual(seen.map((d) => d.result));
  });
});

describe("mailUse", () => {
  it("none-declared: a null MX without signs of sending", () => {
    expect(decideMailUse(facts(nullNoSending))).toBe("none-declared");
  });

  it("mail: a null MX with an SPF that authorizes a sender or any DKIM key not revoked (RFC 7505 §4.2)", () => {
    expect(decideMailUse(facts((f) => (nullNoSending(f), (f.spf.authorizes = true))))).toBe("mail");
    expect(
      decideMailUse(facts((f) => (nullNoSending(f), (f.dkim = { found: true, usable: true, failed: false })))),
    ).toBe("mail");
    // A key that is found but unusable (t=y, short, k=RSA) is still someone's signing key.
    expect(
      decideMailUse(facts((f) => (nullNoSending(f), (f.dkim = { found: true, usable: false, failed: false })))),
    ).toBe("mail");
  });

  // A lookup without an answer is no proof that the domain sends no mail.
  it("mail and at risk: a null MX where SPF or DKIM got no answer", () => {
    expect(decideMailUse(facts((f) => (nullNoSending(f), withFinding("lookup-failed", "spf")(f))))).toBe("mail");
    expect(decideMailUse(facts((f) => (nullNoSending(f), (f.dkim.failed = true))))).toBe("mail");
    // The unanswered lookup counts as a sign of sending, so the null MX puts the mail at risk by
    // row 3.
    expect(delivery(facts((f) => (nullNoSending(f), (f.dkim.failed = true))))).toEqual({ result: "at-risk", rule: 3 });
    expect(delivery(facts((f) => (nullNoSending(f), withFinding("lookup-failed", "spf")(f))))).toEqual({
      result: "at-risk",
      rule: 3,
    });
  });

  it("probably-none also when the MX lookup got no answer: the result shows both paths", () => {
    const f = facts((x) => {
      x.mx = { lookup: "failed", nullMx: false, hosts: 0, usable: 0, unknown: true };
      x.spf.authorizes = false;
      x.dkim = { found: false, usable: false, failed: false };
      withFinding("lookup-failed", "mx")(x);
    });
    expect(decideMailUse(f)).toBe("probably-none");
    expect(delivery(f)).toEqual({ result: "unknown", rule: 6 });
  });

  it("probably-none: no MX, no SPF that authorizes a sender and no DKIM key", () => {
    const f = facts((x) => {
      x.mx = { lookup: "nodata", nullMx: false, hosts: 0, usable: 0, unknown: false };
      x.spf.authorizes = false;
      x.dkim = { found: false, usable: false, failed: false };
    });
    expect(decideMailUse(f)).toBe("probably-none");
  });

  it("mail: any sign of sending, or a lookup that failed", () => {
    const base = (x: Facts) => {
      x.mx = { lookup: "nodata", nullMx: false, hosts: 0, usable: 0, unknown: false };
      x.spf.authorizes = false;
      x.dkim = { found: false, usable: false, failed: false };
    };
    // A send-only domain on Amazon SES without MX: its SPF authorizes the service.
    expect(decideMailUse(facts((x) => (base(x), (x.spf.authorizes = true))))).toBe("mail");
    expect(decideMailUse(facts((x) => (base(x), (x.dkim.found = true))))).toBe("mail");
    expect(decideMailUse(facts((x) => (base(x), (x.dkim.failed = true))))).toBe("mail");
    expect(decideMailUse(facts((x) => (base(x), withFinding("lookup-failed", "spf")(x))))).toBe("mail");
    expect(decideMailUse(facts())).toBe("mail");
  });
});

describe("delivery rules, one test per row of rules.ts", () => {
  it("row 0, no-mail: a null MX without signs of sending", () => {
    expect(delivery(facts(nullNoSending))).toEqual({ result: "no-mail", rule: 0 });
  });

  it("row 1, at-risk: SPF ends in permerror", () => {
    const ids: FindingId[] = [
      "spf-multiple-records",
      "spf-syntax-error",
      "spf-too-many-lookups",
      "spf-too-many-void-lookups",
      "spf-mx-too-many-hosts",
      "spf-include-no-spf",
      "spf-redirect-no-spf",
      "spf-duplicate-modifier",
    ];
    for (const id of ids)
      expect(delivery(facts(withFinding(id))), id).toEqual({ result: "at-risk", rule: 1, cause: id });
  });

  it("row 2, at-risk: every DKIM key found is unusable", () => {
    expect(delivery(facts((f) => (f.dkim.usable = false)))).toEqual({ result: "at-risk", rule: 2 });
  });

  it("row 3, at-risk: no usable MX host, a null MX next to others, or no implicit MX for a domain with mail", () => {
    expect(delivery(facts((f) => (f.mx.usable = 0)))).toEqual({ result: "at-risk", rule: 3 });
    expect(delivery(facts(withFinding("mx-null-with-others")))).toEqual({
      result: "at-risk",
      rule: 3,
      cause: "mx-null-with-others",
    });
    const noImplicit = facts((f) => {
      f.mx = { lookup: "nodata", nullMx: false, hosts: 0, usable: 0, unknown: false };
      withFinding("mx-missing", undefined, { implicit: "none" })(f);
    });
    expect(delivery(noImplicit)).toEqual({ result: "at-risk", rule: 3, cause: "mx-missing" });
    // A null MX on a domain that sends (RFC 7505 §4.2).
    expect(delivery(facts((f) => ((f.mx.nullMx = true), withFinding("mx-null")(f))))).toEqual({
      result: "at-risk",
      rule: 3,
      cause: "mx-null",
    });
    expect(delivery(facts((f) => ((f.mx.usable = 0), withFinding("mx-unresolvable", "mx")(f))))).toEqual({
      result: "at-risk",
      rule: 3,
      cause: "mx-unresolvable",
    });
  });

  it("an MX whose hosts could not be read is unknown, not at risk", () => {
    expect(
      delivery(facts((f) => ((f.mx.usable = 0), (f.mx.unknown = true), withFinding("lookup-failed", "mx")(f)))),
    ).toEqual({ result: "unknown", rule: 6 });
  });

  it("row 4, at-risk: DNSSEC broken on any mail record", () => {
    expect(delivery(facts(withFinding("dnssec-broken", "dkim")))).toEqual({
      result: "at-risk",
      rule: 4,
      cause: "dnssec-broken",
    });
  });

  it("row 5, at-risk: a domain with mail and no DMARC or no SPF", () => {
    expect(delivery(facts((f) => (f.dmarc.effective = undefined)))).toEqual({ result: "at-risk", rule: 5 });
    expect(delivery(facts(withFinding("spf-missing")))).toEqual({ result: "at-risk", rule: 5 });
  });

  it("row 6, unknown: DKIM not found, a lookup failed, or probably no mail", () => {
    expect(delivery(facts((f) => (f.dkim = { found: false, usable: false, failed: false })))).toEqual({
      result: "unknown",
      rule: 6,
    });
    expect(delivery(facts(withFinding("lookup-failed", "transport")))).toEqual({ result: "unknown", rule: 6 });
    expect(delivery(facts((f) => (f.partial = true)))).toEqual({ result: "unknown", rule: 6 });
    const parked = facts((x) => {
      x.mx = { lookup: "nodata", nullMx: false, hosts: 0, usable: 0, unknown: false };
      x.spf.authorizes = false;
      x.dkim = { found: false, usable: false, failed: false };
      x.dmarc.effective = undefined;
      withFinding("spf-missing")(x);
      withFinding("mx-missing", undefined, { implicit: "none" })(x);
    });
    // Probably no mail: missing SPF, DMARC and implicit MX are not delivery problems.
    expect(delivery(parked)).toEqual({ result: "unknown", rule: 6 });
  });

  // The cause is the condition of the row that fired, never just the first delivery finding: not
  // the 1024-bit key when DMARC is missing, nor ptr in SPF when a lookup failed.
  it("each row's cause is its own condition, not the first delivery finding", () => {
    const k1024 = (f: Facts) => withFinding("dkim-key-1024", "dkim")(f);
    expect(delivery(facts((f) => (k1024(f), (f.dmarc.effective = undefined))))).toEqual({ result: "at-risk", rule: 5 });
    expect(delivery(facts((f) => (withFinding("spf-ptr")(f), withFinding("lookup-failed", "mx")(f))))).toEqual({
      result: "unknown",
      rule: 6,
    });
    expect(delivery(facts((f) => (withFinding("spf-ptr")(f), (f.partial = true))))).toEqual({
      result: "unknown",
      rule: 6,
    });
    const unusable = (f: Facts) => {
      f.dkim.usable = false;
      withFinding("spf-ptr")(f);
      f.findings = [...f.findings, finding("dkim-invalid-record", { severity: "info", vars: { reason: "service" } })];
      withFinding("dkim-key-under-1024")(f);
    };
    expect(delivery(facts(unusable))).toEqual({ result: "at-risk", rule: 2, cause: "dkim-key-under-1024" });
    const notFound = (f: Facts) => (
      (f.dkim = { found: false, usable: false, failed: false }),
      withFinding("spf-ptr")(f),
      withFinding("dkim-not-found")(f)
    );
    expect(delivery(facts(notFound))).toEqual({ result: "unknown", rule: 6, cause: "dkim-not-found" });
    // Two permerrors: the first in the report's order.
    expect(
      delivery(
        facts(
          (f) => (
            withFinding("spf-ptr")(f),
            withFinding("spf-too-many-lookups")(f),
            withFinding("spf-multiple-records")(f)
          ),
        ),
      ),
    ).toEqual({ result: "at-risk", rule: 1, cause: "spf-too-many-lookups" });
  });

  it("row 7, ok: SPF valid, a usable DKIM key, DMARC published and every lookup answered", () => {
    expect(delivery(facts())).toEqual({ result: "ok", rule: 7 });
  });

  it("returns rule indexes that match the order of deliveryRules", () => {
    const seen = [
      delivery(facts(nullNoSending)),
      delivery(facts(withFinding("spf-too-many-lookups"))),
      delivery(facts((f) => (f.dkim.usable = false))),
      delivery(facts((f) => (f.mx.usable = 0))),
      delivery(facts(withFinding("dnssec-broken", "dkim"))),
      delivery(facts(withFinding("spf-missing"))),
      delivery(facts((f) => (f.dkim.found = false))),
      delivery(facts()),
    ];
    expect(seen.map((d) => d.rule)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(seen.map((d) => deliveryRules[d.rule]?.result)).toEqual(seen.map((d) => d.result));
  });
});
