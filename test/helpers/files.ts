// Every file under a folder, at any depth, as full paths.
import { readdirSync } from "node:fs";
import { join } from "node:path";

/** The files under `dir`, folders left out. */
export const filesUnder = (dir: string): string[] =>
  readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));
