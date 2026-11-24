// Test titles fit in 120 columns, the width Prettier gives the code: Prettier never splits a
// string, so a longer title runs off the line. The detail goes in a comment above the test.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { filesUnder } from "./helpers/files.ts";

const WIDTH = 120;
// A line that opens a test or a group, or the title line after an it.each or describe.each table.
const TITLE = /^\s*(?:(?:it|test|describe)(?:\.each\(.*\))?\(|\]\)\(|\] as const\)\()["'`]/;

describe("test titles", () => {
  it(`fit in ${WIDTH} columns`, () => {
    const long = filesUnder(fileURLToPath(new URL(".", import.meta.url)))
      .filter((f) => f.endsWith(".ts"))
      .flatMap((f) =>
        readFileSync(f, "utf8")
          .split("\n")
          .flatMap((line, i) => (TITLE.test(line) && [...line].length > WIDTH ? [`${f}:${i + 1}`] : [])),
      );
    expect(long).toEqual([]);
  });
});
