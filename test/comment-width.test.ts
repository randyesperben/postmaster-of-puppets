// Comments fit in 100 characters, so they read in a side-by-side diff; Prettier wraps the code but
// never a comment. Generated files, which say so in their first lines, are left out.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { filesUnder } from "./helpers/files.ts";

const WIDTH = 100;
const FOLDERS = ["../src", "."].map((dir) => fileURLToPath(new URL(dir, import.meta.url)));
// A line comment, or a line that opens or continues a block comment.
const COMMENT = /^\s*(?:\/\/|\/\*|\*)/;
const GENERATED = /\bdo not edit\b/i;

describe("comments", () => {
  it(`fit in ${WIDTH} characters`, () => {
    const long = FOLDERS.flatMap(filesUnder)
      .filter((f) => f.endsWith(".ts"))
      .flatMap((f) => {
        const lines = readFileSync(f, "utf8").split("\n");
        if (GENERATED.test(lines.slice(0, 3).join("\n"))) return [];
        return lines.flatMap((line, i) => (COMMENT.test(line) && [...line].length > WIDTH ? [`${f}:${i + 1}`] : []));
      });
    expect(long).toEqual([]);
  });
});
