import { describe, expect, it } from "vitest";
import { fragmentFor, parseInput, readFragment } from "../src/index.ts";

describe("parseInput: the eight common shapes of input", () => {
  it("a full web address with www., path and query", () => {
    expect(parseInput("https://www.Example.com/contact?x=1")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "www-removed",
    });
  });
  it("an email address", () => {
    expect(parseInput("ana@example.co.uk")).toEqual({
      ok: true,
      domain: "example.co.uk",
      display: "example.co.uk",
      note: "from-email",
    });
  });
  it("a mailto: link", () => {
    expect(parseInput("mailto:Ana@Example.com")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-email",
    });
  });
  it("an internationalized name goes out as punycode and keeps its written form in display", () => {
    expect(parseInput("münchen.de")).toEqual({ ok: true, domain: "xn--mnchen-3ya.de", display: "münchen.de" });
  });
  it("upper case with the final dot", () => {
    expect(parseInput("EXAMPLE.COM.")).toEqual({ ok: true, domain: "example.com", display: "example.com" });
  });
  it("a web address with a port", () => {
    expect(parseInput("http://example.com:8080")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-url",
    });
  });
  it("a single word", () => {
    expect(parseInput("example")).toEqual({ ok: false, error: "not-a-domain" });
  });
  it("an IPv4 address", () => {
    expect(parseInput("192.168.1.1")).toEqual({ ok: false, error: "ip-address" });
  });
});

describe("parseInput: more shapes people paste", () => {
  it("empty or blank", () => {
    expect(parseInput("")).toEqual({ ok: false, error: "empty" });
    expect(parseInput("   \t")).toEqual({ ok: false, error: "empty" });
  });
  it("surrounding spaces and a path without scheme", () => {
    expect(parseInput("  example.org/pricing ")).toEqual({
      ok: true,
      domain: "example.org",
      display: "example.org",
      note: "from-url",
    });
  });
  it("a subdomain other than www stays as it is", () => {
    expect(parseInput("mail.example.net")).toEqual({
      ok: true,
      domain: "mail.example.net",
      display: "mail.example.net",
    });
  });
  it("www. alone before a TLD is a real name", () => {
    expect(parseInput("www.com")).toEqual({ ok: true, domain: "www.com", display: "www.com" });
  });
  it("credentials in a URL and an @ in its path", () => {
    expect(parseInput("https://user:pw@example.com/")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-url",
    });
    expect(parseInput("https://example.com/team@x")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-url",
    });
  });
  it("mailto: with a subject", () => {
    expect(parseInput("mailto:ana@example.com?subject=hi")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-email",
    });
  });
  it("IP addresses in every form the URL parser reads as one", () => {
    for (const ip of [
      "10.0.0.1",
      "1.2.3",
      "0x7f.1",
      "3232235777",
      "[2001:db8::1]",
      "2001:db8::1",
      "::1",
      "http://[::1]:8080/",
    ]) {
      expect(parseInput(ip), ip).toEqual({ ok: false, error: "ip-address" });
    }
  });
  it("things that are not domains", () => {
    for (const bad of [
      "ana@",
      "exa mple.com",
      "-example.com",
      "example-.com",
      "exa_mple.com",
      "example..com",
      "https://",
      "@",
      "http://exa%mple.com",
    ]) {
      expect(parseInput(bad), bad).toEqual({ ok: false, error: "not-a-domain" });
    }
  });
});

describe("parseInput: RFC 1035 §2.3.4 limits", () => {
  const label = (n: number, c = "a") => c.repeat(n);
  it("labels of 63 octets pass, 64 do not", () => {
    expect(parseInput(`${label(63)}.com`)).toMatchObject({ ok: true });
    expect(parseInput(`${label(64)}.com`)).toEqual({ ok: false, error: "too-long" });
  });
  it("names of 253 octets pass, 254 do not", () => {
    const parts = [label(63), label(63), label(63), label(57)];
    const exact = `${parts.join(".")}.com`;
    expect(exact.length).toBe(253);
    expect(parseInput(exact)).toMatchObject({ ok: true, domain: exact });
    expect(parseInput(`a${exact}`)).toEqual({ ok: false, error: "too-long" });
  });
  it("the limits apply to the punycode form", () => {
    // 61 characters as written, 69 octets once xn-- and the punycode suffix are added.
    const idn = `${"a".repeat(60)}ü`;
    expect(idn.length).toBeLessThanOrEqual(63);
    expect(parseInput(`${idn}.de`)).toEqual({ ok: false, error: "too-long" });
  });
});

describe("fragment", () => {
  it("reads a domain from a fragment with a dot", () => {
    expect(readFragment("#example.com")).toBe("example.com");
    expect(readFragment("example.com")).toBe("example.com");
    expect(readFragment("#m%C3%BCnchen.de")).toBe("münchen.de");
    expect(readFragment("# example.com ")).toBe("example.com");
  });
  it("leaves ordinary anchors and broken escapes alone", () => {
    expect(readFragment("")).toBeUndefined();
    expect(readFragment("#")).toBeUndefined();
    expect(readFragment("#spf-too-many-lookups")).toBeUndefined();
    expect(readFragment("#%E0%A4%A.com")).toBeUndefined();
  });
  it("writes the fragment and reads it back", () => {
    expect(fragmentFor("example.com")).toBe("#example.com");
    for (const d of ["example.com", "münchen.de", "xn--mnchen-3ya.de"]) expect(readFragment(fragmentFor(d))).toBe(d);
  });
});

describe("parseInput: tricky characters and pasted record names", () => {
  it("cuts the host at a backslash, which URL parsers treat as a slash", () => {
    expect(parseInput(readFragment("#example.org%5Cis-safe-trust-us") ?? "")).toEqual({
      ok: true,
      domain: "example.org",
      display: "example.org",
      note: "from-url",
    });
    expect(parseInput('example.com\\"onmouseover=alert(1)')).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-url",
    });
  });
  it("never shows ASCII other than letters, digits, dots and hyphens", () => {
    for (const raw of [
      "exa%41mple.com",
      'exa"mple.com',
      "example.com'",
      "exa=mple.com",
      "exam`ple.com",
      "example.com!",
    ]) {
      expect(parseInput(raw), raw).toEqual({ ok: false, error: "not-a-domain" });
    }
  });
  it("reads an address in angle brackets", () => {
    expect(parseInput("Ana <ana@example.com>")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "from-email",
    });
  });
  it("drops a final ideographic full stop and a full-width www", () => {
    expect(parseInput("example.com。")).toEqual({ ok: true, domain: "example.com", display: "example.com" });
    expect(parseInput("ＷＷＷ．example.com")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
      note: "www-removed",
    });
  });
  it("checks the domain of a pasted _dmarc or _domainkey name", () => {
    expect(parseInput("_dmarc.example.com")).toEqual({ ok: true, domain: "example.com", display: "example.com" });
    expect(parseInput("selector1._domainkey.example.com")).toEqual({
      ok: true,
      domain: "example.com",
      display: "example.com",
    });
    expect(parseInput("_DMARC.Example.com.")).toEqual({ ok: true, domain: "example.com", display: "example.com" });
  });
});
