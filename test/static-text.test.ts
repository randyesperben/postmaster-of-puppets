// staticText() gives the texts of a catalog entry with each {placeholder} in its generic form, for
// a list of every finding of a group with no checked domain (the “Everything this checker flags”
// tables of postmasterofpuppets.com). A placeholder written inside a host name or an address
// (_dmarc.{domain}, mail.{domain}, postmaster@{domain}) would then read “_dmarc.your domain”.
import { describe, expect, it } from "vitest";
import { catalog, staticText } from "../src/index.ts";
import { STATIC_FORMS } from "../src/static-text.ts";
import type { Group } from "../src/types.ts";

/** The generic forms glued to a dot or an @ in a text, as staticText() returns it. */
function gluedForms(text: string): string[] {
  const forms = Object.values(STATIC_FORMS).map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  // A dot right before the form, an @ on either side, or a dot after it that a letter, digit or
  // underscore follows (a sentence's own full stop is followed by a space or the end).
  const glued = new RegExp(`[.@](?:${forms.join("|")})|(?:${forms.join("|")})(?:@|\\.[\\w])`, "gi");
  return [...text.matchAll(glued)].map((m) => m[0]);
}

describe("static tables", () => {
  it("finds a generic form glued to a dot or an @", () => {
    expect(gluedForms("Receivers look up _dmarc.your domain and your domain itself.")).toEqual([".your domain"]);
    expect(gluedForms("Anyone can send as mail.your domain.")).toEqual([".your domain"]);
    expect(gluedForms("Write to postmaster@your domain today.")).toEqual(["@your domain"]);
    expect(gluedForms("See your domain.example for details.")).toEqual(["your domain.e"]);
    expect(gluedForms("Anyone can send email as a subdomain of your domain. Fix it.")).toEqual([]);
  });

  // The fix texts are left out here: such a list does not print them, and with a checked domain
  // they carry the real one.
  it("prints no placeholder glued to a dot or an @ in a title or a why", () => {
    // The four groups a check of one record type covers: mx, spf, dkim and dmarc.
    const shown = new Set<string>(["mx", "spf", "dkim", "dmarc"] satisfies Exclude<Group, "transport">[]);
    const glued = catalog
      .filter((e) => shown.has(e.group))
      .flatMap((e) => {
        const { title, why } = staticText(e);
        return [
          ...gluedForms(title).map((g) => `${e.id} title: ${g}`),
          ...gluedForms(why).map((g) => `${e.id} why: ${g}`),
        ];
      });
    expect(glued).toEqual([]);
  });
});

describe("staticText", () => {
  it("leaves no placeholder in any entry, and every text opens with a capital", () => {
    for (const entry of catalog) {
      const t = staticText(entry);
      for (const [part, text] of Object.entries(t)) {
        expect([entry.id, part, text.includes("{")]).toEqual([entry.id, part, false]);
        if (text) expect([entry.id, part, /^[A-Z0-9_]/.test(text)]).toEqual([entry.id, part, true]);
      }
    }
  });

  it("reads each placeholder in its sentence", () => {
    const text = (id: string) => {
      const entry = catalog.find((e) => e.id === id);
      if (!entry) throw new Error(id);
      return staticText(entry);
    };
    expect(text("lookup-failed").title).toBe("A DNS lookup for your domain got no answer");
    expect(text("mx-ok").title).toBe("Your domain has working MX records");
    expect(text("spf-mx-too-many-hosts").title).toBe("An mx term in your SPF points to more than 10 mail servers");
    expect(text("spf-too-many-void-lookups").title).toBe("Your SPF record has more than 2 lookups that find nothing");
    expect(text("dkim-not-found").title).toBe("No DKIM key found with the common selectors");
    const rua = text("dmarc-rua-unauthorized");
    expect(rua.title).toBe("The other domain has not agreed to receive reports for your domain");
    expect(rua.why).toContain(". The other domain publishes no record");
    expect(text("name-is-alias").title).toBe("Your domain is an alias of another name");
    expect(text("dmarc-org-differs").why).toBe(
      "Receivers that follow RFC 9989 take the policy from one name, which gives one policy. Receivers that still use the Public Suffix List take it from another name, which gives a different one. This check counts the weaker one.",
    );
    // Without “or remove them so subdomains follow p=”: with the record at none that closes
    // nothing.
    expect(text("dmarc-subdomains-open").fix).toBe(
      "Set sp= and np= to reject in the DMARC record of your domain or its parent.",
    );
    expect(text("spf-unused-include").title).toBe("Your SPF includes a service, which no other record mentions");
    expect(text("spf-unused-include").why).toBe(
      "No MX record or DKIM key found here points to a service. Does it still send mail for your domain?",
    );
  });

  it("refuses a placeholder with no static form", () => {
    const entry = { ...catalog[0], title: "Lookups for {zone}" } as (typeof catalog)[number];
    expect(() => staticText(entry)).toThrow("no static form for {zone}");
  });
});
