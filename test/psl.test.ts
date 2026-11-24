// psl.ts: the Public Suffix List algorithm that finds the public suffix of a name.
import { describe, expect, it } from "vitest";
import { publicSuffixIn } from "../src/psl.ts";

describe("publicSuffixIn", () => {
  it("PSL matching: longest rule, wildcards and exceptions", () => {
    const rules = new Set(["example.net", "x.example.net", "*.w.example.net", "!keep.w.example.net"]);
    expect(publicSuffixIn("a.example.net", rules)).toBe("example.net");
    expect(publicSuffixIn("y.x.example.net", rules)).toBe("x.example.net");
    expect(publicSuffixIn("a.b.w.example.net", rules)).toBe("b.w.example.net");
    expect(publicSuffixIn("keep.w.example.net", rules)).toBe("w.example.net");
    expect(publicSuffixIn("example.org", rules)).toBeUndefined();
  });
});
