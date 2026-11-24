import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { filesUnder } from "./helpers/files.ts";

// The engine is plain TypeScript that runs unchanged in the browser and in Node 26:
// no imports from outside src/, no DOM, no Buffer, no node: modules.
const ROOT = fileURLToPath(new URL("../src", import.meta.url));

const sources = filesUnder(ROOT).filter((f) => f.endsWith(".ts"));

describe("engine purity", () => {
  it("finds the engine sources", () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  for (const file of sources) {
    it(`${relative(ROOT, file)} stays pure`, () => {
      const code = readFileSync(file, "utf8")
        .replace(/\/\/.*$/gm, "")
        .replace(/\/\*[\s\S]*?\*\//g, "");
      const specifiers = [
        ...code.matchAll(/(?:import|export)[^"';]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)/g),
      ].map((m) => m[1] ?? m[2] ?? "");
      for (const s of specifiers) expect(s.startsWith("./") || s.startsWith("../"), `${file} imports ${s}`).toBe(true);
      // Explicit .ts extensions: Node runs the engine with type stripping (the fixture recorder in
      // the source of postmasterofpuppets.com does), and type stripping resolves no extensionless
      // specifier.
      for (const s of specifiers) expect(s.endsWith(".ts"), `${file} imports ${s} without .ts`).toBe(true);
      for (const s of specifiers) {
        const depth = file.split("/").length - ROOT.split("/").length - 1;
        expect((s.match(/\.\.\//g) ?? []).length, `${file} leaves the engine via ${s}`).toBeLessThanOrEqual(depth);
      }
      expect(code).not.toMatch(/\b(document|window|Buffer|localStorage|navigator)\b/);
      expect(code).not.toMatch(/["']node:/);
      expect(code).not.toMatch(/\brequire\s*\(/);
    });
  }
});
