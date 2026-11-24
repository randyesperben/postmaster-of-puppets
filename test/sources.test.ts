// data/sources/: where each provider value comes from. One source per value of
// providers.ts, one per selector of SELECTORS and a reason per empty list, so the dataset can give
// each value its basis, link, read date and quote. A contribution that adds or changes a value
// fails here until its source is in.
import { describe, expect, it } from "vitest";
import { providerList, providersForInclude, SELECTORS, SHARED_INCLUDES } from "../src/providers.ts";
import {
  type Backing,
  emptyFields,
  flagSources,
  otherSelectors,
  type ProviderField,
  selectorSources,
  valueSources,
} from "../data/sources/index.ts";

const FIELDS: readonly ProviderField[] = ["mx", "spfIncludes", "dkimSelectors", "dkimTargets"];
const key = (provider: string, field: string, value: string) => `${provider} ${field} ${value}`;
const providerValues = providerList.flatMap((p) =>
  FIELDS.flatMap((field) => (p[field] ?? []).map((value) => key(p.id, field, value))),
);
const DAY = /^\d{4}-\d{2}-\d{2}$/;
// Whitespace and case aside, as a page's tags split its text and MBO0001 names mbo0001.
const flat = (s: string) => s.replace(/\s+/g, "").toLowerCase();

function expectBacking(what: string, b: Backing) {
  expect(b.read, what).toMatch(DAY);
  if (b.basis === "vendor") {
    expect(b.url, what).toMatch(/^https:\/\//);
    expect(b.quote?.trim(), what).toBeTruthy();
    expect(b.seenOn, what).toBeUndefined();
  } else if (b.basis === "dns") {
    expect(b.seenOn?.length, what).toBeGreaterThan(0);
    expect(b.quote, what).toBeUndefined();
  } else {
    expect(b.basis, what).toBe("measured");
  }
}

describe("the provider sources, one source per value", () => {
  it("has exactly one entry per value of providerList, and none for a value it does not have", () => {
    const keys = valueSources.map((s) => key(s.provider, s.field, s.value));
    expect(
      keys.filter((k, i) => keys.indexOf(k) !== i),
      "repeated",
    ).toEqual([]);
    expect([...keys].sort()).toEqual([...providerValues].sort());
  });

  it("gives every vendor value its link and quote, and every value seen in DNS where it was seen", () => {
    for (const s of valueSources) expectBacking(key(s.provider, s.field, s.value), s);
  });

  // A quote that does not name its value backs it only through the reader's reasoning: a value
  // whose page gives only a pattern is one seen in DNS.
  it("names each vendor value inside its quote", () => {
    for (const s of valueSources.filter((x) => x.basis === "vendor"))
      expect(flat(s.quote ?? ""), key(s.provider, s.field, s.value)).toContain(flat(s.value));
  });

  it("has exactly one source per selector of SELECTORS, in its order", () => {
    expect(selectorSources.map((s) => s.selector)).toEqual([...SELECTORS]);
    for (const s of selectorSources) expectBacking(`selector ${s.selector}`, s);
  });

  it("gives a selector of a provider's list its value's source, and any other its own with who uses it", () => {
    const listed = new Set(providerList.flatMap((p) => p.dkimSelectors));
    for (const s of selectorSources) {
      const own = valueSources.find((v) => v.field === "dkimSelectors" && v.value === s.selector);
      if (listed.has(s.selector)) {
        expect(s.usedBy, s.selector).toBeUndefined();
        expect({ ...s, selector: undefined }, s.selector).toEqual({
          ...own,
          provider: undefined,
          field: undefined,
          value: undefined,
          selector: undefined,
        });
      } else {
        expect(s.usedBy?.trim(), s.selector).toBeTruthy();
      }
    }
    // No leftovers: every entry of otherSelectors is a selector tried and in no provider's list.
    for (const name of Object.keys(otherSelectors)) {
      expect(SELECTORS, name).toContain(name);
      expect(listed.has(name), name).toBe(false);
    }
  });

  it("gives every empty list one reason, with the page it comes from, and no full list a reason", () => {
    const empty = providerList.flatMap((p) => FIELDS.filter((f) => !(p[f] ?? []).length).map((f) => key(p.id, f, "")));
    const keys = emptyFields.map((s) => key(s.provider, s.field, ""));
    expect(
      keys.filter((k, i) => keys.indexOf(k) !== i),
      "repeated",
    ).toEqual([]);
    expect([...keys].sort()).toEqual([...empty].sort());
    for (const s of emptyFields) {
      const what = key(s.provider, s.field, "(empty)");
      if (s.reason === "not-read") continue;
      expect(s.url, what).toMatch(/^https:\/\//);
      expect(s.read, what).toMatch(DAY);
      if (s.reason === "documented-not-used") {
        expect(s.note?.trim(), what).toBeTruthy();
        // The value the page gives, inside the vendor's words.
        expect(s.documented?.trim(), what).toBeTruthy();
        expect(flat(s.quote ?? ""), what).toContain(flat(s.documented ?? "-"));
      } else {
        expect(s.documented, what).toBeUndefined();
        expect(s.quote, what).toBeUndefined();
      }
    }
  });

  // And has no flag source for a flag providerList does not set.
  it("backs each sendOnly, receiveOnly, spfRedirect and fixMechanisms with the vendor's words", () => {
    const flags = providerList.flatMap((p) =>
      (["sendOnly", "receiveOnly", "spfRedirect", "fixMechanisms"] as const)
        .filter((f) => p[f])
        .map((f) => `${p.id} ${f}`),
    );
    expect(flagSources.map((s) => `${s.provider} ${s.flag}`).sort()).toEqual(flags.sort());
    for (const s of flagSources) expectBacking(`${s.provider} ${s.flag}`, { basis: "vendor", ...s });
    // The record fixes.ts writes is the one the page gives.
    for (const s of flagSources.filter((x) => x.flag === "spfRedirect")) {
      const include = providerList.find((p) => p.id === s.provider)?.spfIncludes[0] ?? "-";
      expect(flat(s.quote), s.provider).toContain(flat(`v=spf1 redirect=${include}`));
    }
    // The mechanisms spf-missing writes before the include are the page's, in its record.
    for (const s of flagSources.filter((x) => x.flag === "fixMechanisms")) {
      const p = providerList.find((x) => x.id === s.provider);
      expect(flat(s.quote), s.provider).toContain(
        flat(["v=spf1", ...(p?.fixMechanisms ?? ["-"]), `include:${p?.spfIncludes[0] ?? "-"}`].join(" ")),
      );
    }
  });

  // The engine-only fields stand on the published ones: a sending MX is one of the provider's MX,
  // and the include a fix writes outside the lists is the one its page gives, kept as
  // documented-not-used in its own empty spfIncludes.
  it("keeps every sendingMx inside the provider's mx, and every fixInclude as its page's documented include", () => {
    for (const p of providerList) {
      for (const m of p.sendingMx ?? []) expect(p.mx, `${p.id} sendingMx ${m}`).toContain(m);
      if (!p.fixInclude) continue;
      const why = emptyFields.find((f) => f.provider === p.id && f.field === "spfIncludes");
      expect(why?.reason, p.id).toBe("documented-not-used");
      expect(why?.documented, p.id).toBe(p.fixInclude);
    }
  });

  // What a shared include holds is the host's (SHARED_INCLUDES in providers.ts): each is a page's
  // include that the dataset gives as documented-not-used, so it names no one either.
  it("backs every shared include with a page that gives it, listed as documented-not-used", () => {
    const documented = emptyFields
      .filter((f) => f.field === "spfIncludes" && f.reason === "documented-not-used")
      .map((f) => f.documented);
    for (const s of SHARED_INCLUDES) {
      expect(documented, s).toContain(s);
      expect(providersForInclude(s), s).toEqual([]);
    }
  });

  it("Amazon SES links the page that gives its MX and SPF values", () => {
    for (const field of ["mx", "spfIncludes"]) {
      const ses = valueSources.find((s) => s.provider === "amazon-ses" && s.field === field);
      expect(ses?.url, field).toBe("https://docs.aws.amazon.com/ses/latest/dg/mail-from.html");
      expect(ses?.basis, field).toBe("vendor");
    }
  });
});
