// fixes.ts: the DKIM record a fix rewrites (lowerKeyTags) and the reports address a fix fills in
// (fillRua) on their own, and the fixes as text to copy (fixesAsText) over full reports. The fixes
// applied back to a zone are the check-fixes scenarios.
import { describe, expect, it } from "vitest";
import { fillRua, fixesAsText, lowerKeyTags } from "../src/fixes.ts";
import { check, googleZone, P4, RUA, SOA } from "./helpers/check.ts";
import type { Node } from "./helpers/zone.ts";

describe("lowerKeyTags", () => {
  it("touches only the values of k= and h=", () => {
    expect(lowerKeyTags("v=DKIM1; K=RSA; k=RSA; h=SHA1:SHA256; n=Keep Case; p=AbC")).toBe(
      "v=DKIM1; K=RSA; k=rsa; h=sha1:sha256; n=Keep Case; p=AbC",
    );
  });
});

// The reports address goes into rua=mailto: encoded where the URI needs it.
// RFC 9989 §4.8: “commas (ASCII 0x2C) and exclamation points (ASCII 0x21) MUST be encoded”;
// RFC 6068 §2: “%”, the gen-delims “/ ? # [ ]” and “& ; =” in a mailto addr-spec (both read on
// rfc-editor.org, 2026-11-18). “;” would also end the DMARC tag.
describe("the reports address in rua=mailto:", () => {
  it("percent-encodes what a mailto URI and the DMARC tag list cannot hold as is", () => {
    expect(fillRua("v=DMARC1; p=none; rua=mailto:{rua}", "a!b,c;d?e#f%g&h=i/j[k]l@example.com")).toBe(
      "v=DMARC1; p=none; rua=mailto:a%21b%2Cc%3Bd%3Fe%23f%25g%26h%3Di%2Fj%5Bk%5Dl@example.com",
    );
    expect(fillRua("rua=mailto:{rua}", "dmarc+reports@example.com")).toBe("rua=mailto:dmarc+reports@example.com");
  });

  it("fixesAsText fills in the same encoded address", async () => {
    const z = googleZone();
    delete z["_dmarc.example.com"];
    const text = fixesAsText(await check(z), "a!b@example.com");
    expect(text).toContain("rua=mailto:a%21b@example.com");
    expect(text).not.toContain("a!b");
  });
});

describe("fixesAsText", () => {
  it("copies the first step of each chain with host and full name, and fills the address", async () => {
    const z = googleZone();
    delete z["_dmarc.example.com"];
    const r = await check(z);
    const text = fixesAsText(r, RUA);
    expect(text).toContain("Host: _dmarc");
    expect(text).toContain("Full name: _dmarc.example.com");
    expect(text).toContain(`New value: v=DMARC1; p=none; rua=mailto:${RUA}`);
    expect(text).toContain("Step 1 of 3. This record starts reports. It does not stop forged mail yet.");
    expect(text).toContain("Most DNS panels want the host.");
    expect(text).not.toContain("p=quarantine");
    expect(fixesAsText(r)).toContain("rua=mailto:{rua}");
  });

  it("shows both paths, the null MX under the no-mail one, when the domain probably sends no mail", async () => {
    const r = await check({ "example.com": { SOA, A: [P4] } });
    const text = fixesAsText(r, RUA);
    const noMail = text.indexOf("If example.com sends no email:");
    const sends = text.indexOf("If it sends email through a service:");
    const mx = text.indexOf("Add MX record\nHost: @\nFull name: example.com\nNew value: 0 .");
    expect(noMail).toBeGreaterThan(-1);
    expect(mx).toBeGreaterThan(noMail);
    expect(mx).toBeLessThan(sends);
  });

  it("is empty when there is nothing to change", async () => {
    expect(fixesAsText(await check(googleZone()), RUA)).toBe("");
  });

  it("writes replace and remove with their current values", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com ~all", "v=spf1 include:sendgrid.net -all"];
    z["sendgrid.net"] = { TXT: ["v=spf1 ip4:192.0.32.0/24 -all"] };
    const text = fixesAsText(await check(z));
    expect(text).toContain(
      "Replace TXT record\nHost: @\nFull name: example.com\nCurrent value: v=spf1 include:_spf.google.com ~all",
    );
    expect(text).toContain(
      "Remove TXT record\nHost: @\nFull name: example.com\nValue: v=spf1 include:sendgrid.net -all",
    );
  });
});
