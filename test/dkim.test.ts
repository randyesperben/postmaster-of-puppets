import { describe, expect, it } from "vitest";
import { checkDkim, parseKey, rsaModulusBits } from "../src/checks/dkim.ts";
import { SELECTORS } from "../src/providers.ts";
import type { Resolver } from "../src/dns/types.ts";
import { key, run } from "./helpers/dkim.ts";
import { chunks } from "./helpers/dns.ts";
import { ids, idsWithSeverity } from "./helpers/findings.ts";
import { rsaKey } from "./helpers/keys.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

// RFC 8463 Appendix A.2: the public key of RFC 8032 §7.1, Test 1.
const ED25519 = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex").toString(
  "base64",
);

describe("RSA key size from DER", () => {
  for (const bits of [512, 1024, 2048, 4096] as const) {
    it(`${bits} bits, SubjectPublicKeyInfo and PKCS#1`, () => {
      expect(rsaModulusBits(Buffer.from(rsaKey(bits), "base64"))).toBe(bits);
      expect(rsaModulusBits(Buffer.from(rsaKey(bits, "pkcs1"), "base64"))).toBe(bits);
    });
  }

  /** A PKCS#1 RSAPublicKey whose modulus is `bits` long, written by hand. */
  function pkcs1(bits: number): Uint8Array {
    const bytes = Math.ceil(bits / 8);
    const top = 2 ** (((bits - 1) % 8) + 1) - 1;
    const modulus = [top, ...Array<number>(bytes - 1).fill(0xff)];
    const int = modulus[0]! & 0x80 ? [0, ...modulus] : modulus;
    const len = (n: number) => (n < 128 ? [n] : [0x81, n]);
    const body = [0x02, ...len(int.length), ...int, 0x02, 0x03, 0x01, 0x00, 0x01];
    return Uint8Array.from([0x30, ...len(body.length), ...body]);
  }

  it("lengths that are not a multiple of 8, on both sides of 1024", async () => {
    expect(rsaModulusBits(pkcs1(1023))).toBe(1023);
    expect(rsaModulusBits(pkcs1(1025))).toBe(1025);
    const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
    expect(ids(await run(key("s1", `v=DKIM1; p=${b64(pkcs1(1023))}`)))).toEqual(["dkim-key-under-1024"]);
    expect(ids(await run(key("s1", `v=DKIM1; p=${b64(pkcs1(1025))}`)))).toEqual(["dkim-key-1024"]);
  });

  it("refuses what is not an RSA key", () => {
    for (const bad of [
      [],
      [0x30],
      [0x02, 0x01, 0x00],
      [0x30, 0x03, 0x02, 0x01, 0x00],
      [0x30, 0x85, 1, 1, 1, 1, 1],
      [0x30, 0x80],
      [0x30, 0x05, 0x30, 0x00, 0x03, 0x01, 0x01],
      [0x30, 0x04, 0x30, 0x00, 0x04, 0x00],
      [0x30, 0x05, 0x02, 0x10, 0x00],
    ]) {
      expect(rsaModulusBits(Uint8Array.from(bad)), JSON.stringify(bad)).toBeUndefined();
    }
  });
});

describe("key records (RFC 6376 §3.6.1)", () => {
  it("reads a 2048-bit key split over several strings", async () => {
    const r = await run(key("google", chunks(`v=DKIM1; k=rsa; p=${rsaKey(2048)}`)));
    expect(ids(r)).toEqual(["dkim-ok"]);
    expect(r.keys).toEqual([{ selector: "google", algorithm: "rsa", bits: 2048, revoked: false }]);
    expect(r.usable).toBe(true);
    expect(r.status).toBe("pass");
    expect(r.selectorsTried).toBe(SELECTORS.length);
  });

  it("keeps v= optional and whitespace inside p= harmless", () => {
    const b64 = rsaKey(2048);
    const spaced = `${b64.slice(0, 100)} ${b64.slice(100)}`;
    expect(parseKey("s", `k=rsa; p=${spaced}`).usable).toBe(true);
  });

  it("dkim-invalid-record: bad v=, v= not first, unknown k=, no p=, p= not base64, p= not a key", async () => {
    for (const rec of [
      "v=DKIM2; p=AAAA",
      "k=rsa; v=DKIM1; p=AAAA",
      "v=DKIM1; k=dsa; p=AAAA",
      "v=DKIM1; k=rsa",
      "v=DKIM1; p=***",
      "v=DKIM1; p=AAAA",
      `v=DKIM1; k=ed25519; p=${rsaKey(1024)}`,
    ]) {
      const r = await run(key("mail", rec));
      expect(ids(r), rec).toEqual(["dkim-invalid-record"]);
      expect(r.usable).toBe(false);
      expect(r.status).toBe("weak");
    }
  });

  it("dkim-key-under-1024", async () => {
    const r = await run(key("s1", `v=DKIM1; p=${rsaKey(512)}`));
    expect(ids(r)).toEqual(["dkim-key-under-1024"]);
    expect(r.usable).toBe(false);
    expect(r.status).toBe("fail");
  });

  it("dkim-key-1024: usable, with a warning", async () => {
    const r = await run(key("s1", `v=DKIM1; p=${rsaKey(1024, "pkcs1")}`));
    expect(ids(r)).toEqual(["dkim-key-1024"]);
    expect(r.usable).toBe(true);
    expect(r.keys[0]?.bits).toBe(1024);
  });

  it("dkim-sha1-only, while sha1:sha256 is fine", async () => {
    expect(ids(await run(key("k1", `v=DKIM1; h=sha1; p=${rsaKey(2048)}`)))).toEqual(["dkim-sha1-only"]);
    expect(ids(await run(key("k1", `v=DKIM1; h=sha1:sha256; p=${rsaKey(2048)}`)))).toEqual(["dkim-ok"]);
  });

  it("dkim-testing-mode", async () => {
    expect(ids(await run(key("k1", `v=DKIM1; t=y:s; p=${rsaKey(2048)}`)))).toEqual(["dkim-testing-mode"]);
  });

  it("dkim-revoked: an empty p= (Fastmail's rotated selectors), harmless next to a live key", async () => {
    const zone = {
      ...key("fm1", "n=Intentionally_Left_Blank_As_Per_DKIM_Rotation_BCP; p="),
      ...key("fm2", `v=DKIM1; p=${rsaKey(2048)}`),
    };
    const r = await run(zone);
    expect(ids(r)).toEqual(["dkim-revoked", "dkim-ok"]);
    expect(r.keys.find((k) => k.selector === "fm1")?.revoked).toBe(true);
    const alone = await run(key("fm1", "v=DKIM1; p="));
    // A revoked key is no key: the same as nothing published.
    expect(ids(alone)).toEqual(["dkim-revoked", "dkim-not-found"]);
    expect(alone.usable).toBe(false);
    expect(alone.found).toBe(false);
  });

  it("dkim-ed25519-only, and not when an RSA key signs too", async () => {
    const only = await run(key("brisbane", `v=DKIM1; k=ed25519; p=${ED25519}`), ["brisbane"]);
    expect(ids(only)).toEqual(["dkim-ed25519-only", "dkim-ok"]);
    expect(only.keys[0]).toEqual({ selector: "brisbane", algorithm: "ed25519", revoked: false });
    const both = await run(
      { ...key("brisbane", `v=DKIM1; k=ed25519; p=${ED25519}`), ...key("google", `v=DKIM1; p=${rsaKey(2048)}`) },
      ["brisbane"],
    );
    expect(ids(both)).toEqual(["dkim-ok"]);
  });

  it("dkim-not-found with the common selectors: status unknown, never a failure", async () => {
    const r = await run({ "example.com": { MX: ["10 mx.example.com"] } });
    expect(ids(r)).toEqual(["dkim-not-found"]);
    expect(r.findings[0]?.vars?.tried).toBe(SELECTORS.length);
    expect(r.status).toBe("unknown");
    expect(r.found).toBe(false);
  });

  it("tries a selector typed by the user, ignoring one that is not a selector", async () => {
    const resolver = zoneResolver(key("20260101pm", `v=DKIM1; p=${rsaKey(1024)}`));
    const r = await checkDkim({ resolver }, "example.com", [" 20260101PM ", "bad selector!", "google"]);
    expect(r.keys.map((k) => k.selector)).toEqual(["20260101pm"]);
    expect(r.selectorsTried).toBe(SELECTORS.length + 1);
    // By the start of the name: the random probe (pmp- and 8 hex digits, randomProbeSelector) holds
    // "bad" in about 1 run in 680, so a search anywhere in the query would fail now and then.
    expect(resolver.asked.filter((q) => q.startsWith("bad"))).toEqual([]);
  });

  it("dkim-dangling-cname: a selector whose CNAME target is gone", async () => {
    const r = await run({
      "k1._domainkey.example.com": { CNAME: ["dkim.old-provider.example.net"] },
      ...key("google", `v=DKIM1; p=${rsaKey(2048)}`),
    });
    expect(ids(r)).toEqual(["dkim-dangling-cname", "dkim-ok"]);
    expect(r.findings[0]?.found).toBe("k1._domainkey.example.com CNAME dkim.old-provider.example.net");
  });

  it("a key reached through a CNAME records it", async () => {
    const r = await run({
      "s1._domainkey.example.com": { CNAME: ["s1.domainkey.u1.wl1.sendgrid.example.net"] },
      "s1.domainkey.u1.wl1.sendgrid.example.net": { TXT: [`v=DKIM1; p=${rsaKey(2048)}`] },
    });
    expect(r.keys[0]?.viaCname).toBe("s1.domainkey.u1.wl1.sendgrid.example.net");
  });

  it("lookup-failed when no selector lookup answers, or some fail and nothing is found", async () => {
    const down: Resolver = { query: () => Promise.reject(new Error("down")) };
    const all = await checkDkim({ resolver: down }, "example.com");
    expect(ids(all)).toEqual(["lookup-failed"]);
    expect(all.failed).toBe(true);
    expect(all.status).toBe("unknown");
    const some = await run({ "google._domainkey.example.com": { $unreachable: true } });
    expect(ids(some)).toEqual(["lookup-failed"]);
    expect(some.findings[0]?.found).toBe("some _domainkey lookup");
  });
});

// Against RFC 6376 as published on rfc-editor.org (read 2026-11-18).
describe("key records, strict reading (RFC 6376 §3.2, §3.6.1, §3.6.2.2, §6.1.2)", () => {
  it("a selector whose full name passes 253 octets is never asked, typed or built in", async () => {
    const fits = `${[..."abc"].map((c) => c.repeat(63)).join(".")}.${"d".repeat(38)}`;
    expect(`${fits}._domainkey.example.com`.length).toBe(253);
    const resolver = zoneResolver({});
    await checkDkim({ resolver }, "example.com", [fits, `${fits}e`]);
    expect(resolver.asked.some((q) => q.startsWith(`${fits}._domainkey`))).toBe(true);
    expect(resolver.asked.some((q) => q.startsWith(`${fits}e.`))).toBe(false);

    const long = `${[..."abc"].map((c) => c.repeat(63)).join(".")}.${"d".repeat(35)}.com`;
    const near = zoneResolver({});
    const r = await checkDkim({ resolver: near }, long);
    expect(near.asked.length).toBeGreaterThan(0);
    for (const q of near.asked) expect(q.split(" ")[0]!.length, q).toBeLessThanOrEqual(253);
    expect(r.selectorsTried).toBe(near.asked.length);
  });

  it("two key records at one selector are invalid, whatever their order", async () => {
    for (const recs of [
      [`v=DKIM1; p=${rsaKey(512)}`, `v=DKIM1; p=${rsaKey(2048)}`],
      [`v=DKIM1; p=${rsaKey(2048)}`, `v=DKIM1; p=${rsaKey(512)}`],
    ]) {
      const r = await run({ "s1._domainkey.example.com": { TXT: recs } });
      expect(ids(r)).toEqual(["dkim-invalid-record"]);
      expect(r.usable).toBe(false);
      expect(r.found).toBe(true);
    }
  });

  it("a key whose s= lists neither email nor * is not a mail key", async () => {
    const tls = await run(key("s1", `v=DKIM1; k=rsa; s=tlsrpt; p=${rsaKey(2048)}`));
    expect(idsWithSeverity(tls)).toEqual(["dkim-invalid-record:info", "dkim-not-found:info"]);
    expect(tls.findings[0]?.vars?.reason).toBe("service");
    expect(tls).toMatchObject({ usable: false, found: false, keys: [] });
    for (const s of ["email", "*", "tlsrpt:email", "tlsrpt : *"]) {
      expect(ids(await run(key("s1", `v=DKIM1; s=${s}; p=${rsaKey(2048)}`))), s).toEqual(["dkim-ok"]);
    }
    expect(ids(await run(key("s1", `v=DKIM1; s=EMAIL; p=${rsaKey(2048)}`)))).toEqual([
      "dkim-invalid-record",
      "dkim-not-found",
    ]);
  });

  it("a repeated tag makes the whole record invalid", async () => {
    for (const rec of [
      `v=DKIM1; p=${rsaKey(2048)}; p=`,
      `v=DKIM1; p=; p=${rsaKey(2048)}`,
      `v=DKIM1; k=rsa; k=rsa; p=${rsaKey(2048)}`,
    ]) {
      const r = await run(key("s1", rec));
      expect(ids(r), rec).toEqual(["dkim-invalid-record"]);
      expect(r.usable).toBe(false);
    }
  });

  it("a key behind broken DNSSEC is reported and not usable", async () => {
    const r = await run({ "s1._domainkey.example.com": { TXT: [`v=DKIM1; p=${rsaKey(2048)}`], $servfail: true } });
    expect(r.findings.map((f) => `${f.id}:${f.group}`)).toEqual(["dnssec-broken:dkim"]);
    expect(r.findings[0]?.found).toBe("s1._domainkey.example.com TXT");
    expect(r).toMatchObject({ usable: false, found: true, status: "fail" });
    expect(r.keys.map((k) => k.selector)).toEqual(["s1"]);
    const zone: Zone = Object.fromEntries(SELECTORS.map((s) => [`${s}._domainkey.example.com`, { $servfail: true }]));
    const all = await run(zone);
    expect(ids(all)).toEqual(["dnssec-broken", "dkim-not-found"]);
    expect(all.findings[0]?.found).toBe("every <selector>._domainkey.example.com TXT");
  });

  it("revoked keys are kept in keys but are not found, and several give one finding", async () => {
    const r = await run({ ...key("fm1", "v=DKIM1; p="), ...key("fm2", "v=DKIM1; p=") });
    expect(ids(r)).toEqual(["dkim-revoked", "dkim-not-found"]);
    expect(r.findings[0]?.found).toBe("fm1, fm2");
    expect(r.keys.map((k) => [k.selector, k.revoked])).toEqual([
      ["fm1", true],
      ["fm2", true],
    ]);
    expect(r).toMatchObject({ found: false, usable: false, status: "unknown" });
  });

  it("keys only in testing mode are not usable; a key outside testing mode is", async () => {
    const only = await run(key("k1", `v=DKIM1; t=y; p=${rsaKey(2048)}`));
    expect(ids(only)).toEqual(["dkim-testing-mode"]);
    expect(only).toMatchObject({ usable: false, found: true, status: "weak" });
    expect(parseKey("k1", `v=DKIM1; t=s:y; p=${rsaKey(2048)}`).usable).toBe(false);
    const mixed = await run({
      ...key("k1", `v=DKIM1; t=y; p=${rsaKey(2048)}`),
      ...key("google", `v=DKIM1; p=${rsaKey(2048)}`),
    });
    expect(mixed.usable).toBe(true);
  });

  it("tag names, v=, k= and h= values are case-sensitive (RFC 6376 §3.2)", async () => {
    const b = rsaKey(2048);
    // k=RSA and h=SHA256 are invalid records, with what is wrong in found.
    for (const rec of [
      `V=DKIM1; P=${b}`,
      `v=DKIM1; P=${b}`,
      `v=dkim1; p=${b}`,
      `v=DKIM1; k=RSA; p=${b}`,
      `v=DKIM1; h=SHA256; p=${b}`,
    ]) {
      expect(ids(await run(key("s1", rec))), rec).toEqual(["dkim-invalid-record"]);
    }
    expect((await run(key("s1", `v=DKIM1; k=RSA; p=${b}`))).findings[0]?.found).toBe("s1: unknown key type k=RSA");
    expect((await run(key("s1", `v=DKIM1; h=SHA256; p=${b}`))).findings[0]?.found).toBe(
      "s1: h=SHA256 allows no sha256",
    );
    // The upper-case forms carry reason "case"; other unknown values do not.
    expect((await run(key("s1", `v=DKIM1; k=RSA; p=${b}`))).findings[0]?.vars?.reason).toBe("case");
    expect((await run(key("s1", `v=DKIM1; k=Ed25519; p=${b}`))).findings[0]?.vars?.reason).toBe("case");
    expect((await run(key("s1", `v=DKIM1; h=SHA256; p=${b}`))).findings[0]?.vars?.reason).toBe("case");
    expect((await run(key("s1", `v=DKIM1; k=dsa; p=${b}`))).findings[0]?.vars?.reason).toBeUndefined();
    expect((await run(key("s1", `v=DKIM1; h=md5; p=${b}`))).findings[0]?.vars?.reason).toBeUndefined();
    expect(ids(await run(key("s1", `v=DKIM1; h=SHA1:sha256; p=${b}`)))).toEqual(["dkim-ok"]);
    expect(ids(await run(key("s1", `v=DKIM1; h=sha1; p=${b}`)))).toEqual(["dkim-sha1-only"]);
    // t=Y is an unknown flag, ignored: the key is not in testing mode.
    expect(ids(await run(key("s1", `v=DKIM1; t=Y; p=${b}`)))).toEqual(["dkim-ok"]);
  });

  it("a part that is not tag=value is a syntax error; a final ; is fine", async () => {
    const b = rsaKey(2048);
    for (const rec of [`v=DKIM1; garbage; p=${b}`, `v=DKIM1;; p=${b}`, `v=DKIM1; 1x=2; p=${b}`]) {
      expect(ids(await run(key("s1", rec))), rec).toEqual(["dkim-invalid-record"]);
    }
    expect(ids(await run(key("s1", `v=DKIM1; p=${b};`)))).toEqual(["dkim-ok"]);
    expect(ids(await run(key("s1", `v=DKIM1;\tk=rsa;\r\n p=${b} ; `)))).toEqual(["dkim-ok"]);
  });

  it("an h= without sha256 cannot verify an RSA-SHA256 signature", async () => {
    const r = await run(key("s1", `v=DKIM1; h=md5; p=${rsaKey(2048)}`));
    expect(ids(r)).toEqual(["dkim-invalid-record"]);
    expect(r.usable).toBe(false);
    expect(ids(await run(key("s1", `v=DKIM1; h=sha256; p=${rsaKey(2048)}`)))).toEqual(["dkim-ok"]);
    expect(ids(await run(key("s1", `v=DKIM1; h=sha1:md5; p=${rsaKey(2048)}`)))).toEqual(["dkim-sha1-only"]);
    expect(ids(await run(key("s1", `v=DKIM1; h=; p=${rsaKey(2048)}`)))).toEqual(["dkim-invalid-record"]);
  });

  it("a key-like record with no v= and no p= is invalid, while other TXT is ignored", async () => {
    const r = await run(key("s1", "k=rsa; t=y"));
    expect(ids(r)).toEqual(["dkim-invalid-record"]);
    expect(r.found).toBe(true);
    expect(ids(await run(key("s1", "v=spf1 -all")))).toEqual(["dkim-not-found"]);
  });

  it("dkim-ed25519-only when the only usable key is Ed25519, next to a weak RSA key", async () => {
    const r = await run(
      { ...key("brisbane", `v=DKIM1; k=ed25519; p=${ED25519}`), ...key("s1", `v=DKIM1; p=${rsaKey(512)}`) },
      ["brisbane"],
    );
    expect(ids(r)).toEqual(["dkim-key-under-1024", "dkim-ed25519-only"]);
    expect(r.usable).toBe(true);
  });

  it("a selector without an answer is listed beside found keys; lookup-failed when none is usable", async () => {
    const good = await run({
      "google._domainkey.example.com": { $unreachable: true },
      ...key("s1", `v=DKIM1; p=${rsaKey(2048)}`),
    });
    expect(good).toMatchObject({ noAnswer: ["google"], failed: false, found: true, usable: true });
    expect(ids(good)).toEqual(["dkim-ok"]);
    const weak = await run({
      "google._domainkey.example.com": { $unreachable: true },
      ...key("s1", `v=DKIM1; p=${rsaKey(512)}`),
    });
    expect(ids(weak)).toEqual(["dkim-key-under-1024", "lookup-failed"]);
    expect(weak).toMatchObject({ noAnswer: ["google"], failed: false, status: "fail" });
    const invalid = await run({
      "google._domainkey.example.com": { $unreachable: true },
      ...key("s1", "v=DKIM1; p=***"),
    });
    expect(invalid.status).toBe("unknown");
    expect((await run(key("s1", `v=DKIM1; p=${rsaKey(2048)}`))).noAnswer).toEqual([]);
  });

  it("dkim-key-1024 carries the key length", async () => {
    const r = await run(key("s1", `v=DKIM1; p=${rsaKey(1024)}`));
    expect(r.findings[0]?.vars?.bits).toBe(1024);
  });
});
