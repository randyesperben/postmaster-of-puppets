import { describe, expect, it } from "vitest";
import { DEFAULT_ORDER, ENDPOINT_URLS } from "../src/dns/endpoints.ts";
import { operators } from "../src/index.ts";

describe("operators", () => {
  it("lists the six operators in the order the engine asks them", () => {
    expect(operators.map((o) => o.id)).toEqual([...DEFAULT_ORDER]);
    expect(operators).toHaveLength(6);
  });

  it("names each one and links its endpoint and an https privacy policy", () => {
    const names = new Set(operators.map((o) => o.name));
    expect(names.size).toBe(6);
    for (const o of operators) {
      expect(o.name).not.toBe("");
      expect(ENDPOINT_URLS).toContain(o.url);
      expect(o.privacy).toMatch(/^https:\/\/[a-z0-9.-]+\//);
    }
  });
});
