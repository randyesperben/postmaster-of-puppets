// ip.ts: reading IPv4 and IPv6 addresses, and which ranges are private, reserved or not globally
// reachable.
import { describe, expect, it } from "vitest";
import { isUnreachableAddress, parseIpv4, parseIpv6 } from "../src/ip.ts";
import { P4, P6 } from "./helpers/check.ts";

describe("ip", () => {
  it("parses IPv4 strictly", () => {
    expect(parseIpv4("192.0.2.1")).toEqual([192, 0, 2, 1]);
    for (const bad of ["256.1.1.1", "1.2.3", "01.2.3.4", "a.b.c.d"]) expect(parseIpv4(bad), bad).toBeUndefined();
  });

  it("parses IPv6, with :: and an embedded IPv4", () => {
    expect(parseIpv6("2001:db8::1")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(parseIpv6("::")).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(parseIpv6("::ffff:192.0.2.1")).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x201]);
    expect(parseIpv6("1:2:3:4:5:6:7:8")).toHaveLength(8);
    for (const bad of ["1::2::3", "1:2:3", "12345::", "::ffff:999.0.0.1", "192.0.2.1", "g::1", "1:2:3:4:5:6:7::8:9"]) {
      expect(parseIpv6(bad), bad).toBeUndefined();
    }
  });

  it("knows the private and reserved ranges", () => {
    for (const ip of [
      "10.1.2.3",
      "172.31.0.1",
      "192.168.0.1",
      "127.0.0.1",
      "169.254.1.1",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
      "::1",
      "::",
      "fd12::1",
      "fe80::1",
      "ff02::1",
      "::ffff:10.0.0.1",
    ]) {
      expect(isUnreachableAddress(ip), ip).toBe(true);
    }
    for (const ip of ["172.32.0.1", "8.8.8.8", "2a00:1450::1", "not-an-ip"]) {
      expect(isUnreachableAddress(ip), ip).toBe(false);
    }
  });

  it("follows the IANA special-purpose registries, Globally Reachable column", () => {
    // iana-ipv4-special-registry and iana-ipv6-special-registry, read on 2026-11-18.
    const unreachable = [
      "192.0.2.1",
      "198.51.100.1",
      "203.0.113.1",
      "198.18.0.1",
      "198.19.255.255",
      "192.0.0.5",
      "192.0.0.170",
      "192.88.99.2",
      "2001:db8::1",
      "3fff::1",
      "100::1",
      "100:0:0:1::1",
      "64:ff9b:1::1",
      "2001::1",
      "2001:2::1",
      "2001:10::1",
      "5f00::1",
      "::ffff:8.8.8.8",
    ];
    for (const ip of unreachable) expect(isUnreachableAddress(ip), ip).toBe(true);
    const reachable = [
      "192.0.0.9",
      "192.0.0.10",
      "192.31.196.1",
      "192.175.48.1",
      "64:ff9b::808:808",
      "2001:1::1",
      "2001:1::3",
      "2001:3::1",
      "2001:4:112::1",
      "2001:20::1",
      "2001:30::1",
      "2620:4f:8000::1",
      P4,
      P6,
    ];
    for (const ip of reachable) expect(isUnreachableAddress(ip), ip).toBe(false);
  });
});
