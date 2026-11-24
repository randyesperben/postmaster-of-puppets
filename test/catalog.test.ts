import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { catalog, FINDING_IDS } from "../src/index.ts";
import { filesUnder } from "./helpers/files.ts";

// The guide pages of postmasterofpuppets.com that a finding may link to.
const GUIDES = new Set([
  "/guides/spf/too-many-dns-lookups/",
  "/guides/spf/multiple-spf-records/",
  "/guides/dkim/old-provider-records/",
  "/guides/dmarc/p-none-to-reject/",
  "/guides/dmarc/aggregate-reports/",
  "/guides/providers/switch-without-losing-mail/",
  "/guides/providers/cloudflare-email-routing/",
  "/guides/spoofing/domains-that-send-no-email/",
  "/guides/providers/self-hosting-vs-provider/",
  "/guides/sender-requirements/",
]);
const ANY_GROUP = new Set(["lookup-failed", "dnssec-broken", "name-is-alias"]);
// Ids whose texts are written but that no check raises yet. Empty for now: a new id that waits for
// its check goes here, and the last test below fails as soon as a test provokes it.
const NOT_PROVOKED = new Set<string>();

describe("catalog", () => {
  it("has exactly one entry per finding id, in FINDING_IDS order", () => {
    expect(catalog.map((e) => e.id)).toEqual([...FINDING_IDS]);
  });

  it("uses group any only for lookup-failed, dnssec-broken and name-is-alias", () => {
    for (const e of catalog) expect(e.group === "any", e.id).toBe(ANY_GROUP.has(e.id));
  });

  it("matches each id prefix with its group", () => {
    const prefix: Record<string, string> = {
      mx: "mx",
      spf: "spf",
      dmarc: "dmarc",
      dkim: "dkim",
      mta: "transport",
      tls: "transport",
    };
    for (const e of catalog) {
      const p = e.id.split("-")[0] ?? "";
      if (p in prefix) expect(e.group, e.id).toBe(prefix[p]);
    }
  });

  it("gives pass severity only to the *-ok and dmarc-enforced entries", () => {
    for (const e of catalog) expect(e.severity === "pass", e.id).toBe(/-ok$|^dmarc-enforced$/.test(e.id));
  });

  it("links only to the guide pages listed above", () => {
    for (const e of catalog) if (e.guide) expect(GUIDES.has(e.guide.split("#")[0] ?? ""), e.id).toBe(true);
  });

  it("links each guide problem to its guide", () => {
    const byId = new Map(catalog.map((e) => [e.id, e.guide]));
    expect(byId.get("spf-too-many-lookups")).toBe("/guides/spf/too-many-dns-lookups/");
    expect(byId.get("spf-multiple-records")).toBe("/guides/spf/multiple-spf-records/");
    expect(byId.get("dkim-unused-provider")).toBe("/guides/dkim/old-provider-records/");
    expect(byId.get("dmarc-policy-none")).toBe("/guides/dmarc/p-none-to-reject/");
    expect(byId.get("dmarc-no-rua")).toBe("/guides/dmarc/aggregate-reports/");
    expect(byId.get("mx-missing")).toBeDefined();
    expect(byId.get("dkim-dangling-cname")?.startsWith("/guides/dkim/old-provider-records/")).toBe(true);
  });

  it("has no TODO left in titles, texts or sources", () => {
    const todo = catalog.filter((e) =>
      [e.title, e.why, e.fix, e.source.label, e.source.url].some((t) => t.includes("TODO")),
    );
    expect(todo.map((e) => e.id)).toEqual([]);
  });

  it("writes a title and a why for every entry, and a fix for all but the passes and the two questions", () => {
    const noFix = new Set(["spf-unused-include", "dkim-unused-provider"]);
    for (const e of catalog) {
      expect(e.title.length, e.id).toBeGreaterThan(10);
      expect(e.title, e.id).not.toContain("\n");
      expect(e.why.length, e.id).toBeGreaterThan(20);
      expect(e.fix === "", e.id).toBe(e.severity === "pass" || noFix.has(e.id));
    }
  });

  it("uses only {domain} and the vars each finding always carries", () => {
    const vars: Record<string, string[]> = {
      "spf-too-many-void-lookups": ["count"],
      "spf-mx-too-many-hosts": ["hosts"],
      "spf-unused-include": ["provider"],
      "dmarc-subdomains-open": ["sp", "np", "at"],
      "dmarc-rua-unauthorized": ["host"],
      "dkim-not-found": ["tried"],
      "dkim-unused-provider": ["provider"],
      "name-is-alias": ["target"],
      "dmarc-org-differs": ["orgDomain", "policy", "pslOrgDomain", "pslPolicy"],
    };
    for (const e of catalog) {
      const allowed = new Set(["domain", ...(vars[e.id] ?? [])]);
      const used = [e.title, e.why, e.fix].join(" ").match(/\{[A-Za-z]+\}/g) ?? [];
      for (const m of used) expect(allowed.has(m.slice(1, -1)), `${e.id} ${m}`).toBe(true);
    }
  });

  it("cites an RFC section on rfc-editor.org or a page of an allowed vendor", () => {
    const vendors = new Set(["support.google.com"]);
    for (const e of catalog) {
      const { label, url } = e.source;
      const rfcUrl = /^https:\/\/www\.rfc-editor\.org\/rfc\/rfc(\d+)\.html#(section|appendix)-([\dA-Z.]+)$/.exec(url);
      if (rfcUrl) {
        expect(label, e.id).toContain(
          rfcUrl[2] === "section" ? `RFC ${rfcUrl[1]} §${rfcUrl[3]}` : `RFC ${rfcUrl[1]} Appendix ${rfcUrl[3]}`,
        );
        // RFC 7489 is obsolete: only dmarc-pct cites it, and names RFC 9989 next to it.
        if (rfcUrl[1] === "7489") expect(label, e.id).toContain("RFC 9989");
      } else {
        expect(vendors.has(new URL(url).hostname), `${e.id} ${url}`).toBe(true);
        expect(url, e.id).toMatch(/^https:\/\//);
      }
    }
  });

  // A sender that cached the policy keeps applying it until its max_age runs out (RFC 8461 §3.3),
  // and MTA-STS is retired with a mode none policy first (§8.3).
  it("mta-sts-policy-unreachable says that a cached policy still applies, and how to retire MTA-STS", () => {
    const e = catalog.find((x) => x.id === "mta-sts-policy-unreachable");
    for (const text of [e?.why, e?.variants?.[0]?.why]) {
      expect(text).toContain("have not stored your policy before");
      expect(text).toContain("keep applying it until its max_age runs out");
    }
    expect(e?.fix).toContain("mode: none");
    expect(e?.fix).toContain("once the old policy’s max_age has passed");
  });

  // A finding id counts as provoked when another engine test names it, written "<id>": a test
  // that raises it, or one that asserts it is absent. NOT_PROVOKED holds the ids no test names yet.
  it("names every finding id in some test, but the ids no check raises yet", () => {
    const self = fileURLToPath(import.meta.url);
    const text = filesUnder(fileURLToPath(new URL(".", import.meta.url)))
      .filter((f) => f.endsWith(".test.ts") && f !== self)
      .map((f) => readFileSync(f, "utf8"))
      .join("\n");
    expect(FINDING_IDS.filter((id) => NOT_PROVOKED.has(id) === text.includes(`"${id}"`))).toEqual([]);
  });
});
