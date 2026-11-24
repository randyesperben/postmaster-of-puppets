// The engine's public surface: what code outside the engine imports comes from index.ts and is the
// same object the engine uses. The list of names is fixed here, so a change to what the package
// exports is a visible change to this test.
import { describe, expect, it } from "vitest";
import * as engine from "../src/index.ts";
import { checkAlignment as alignmentFn } from "../src/alignment.ts";
import { checkAlignment, receiverRules } from "../src/index.ts";
import { receiverRules as rows } from "../src/receivers.ts";

describe("index.ts", () => {
  it("exports receiverRules and the alignment check", () => {
    expect(receiverRules).toBe(rows);
    expect(checkAlignment).toBe(alignmentFn);
  });

  it("exports these names and no others", () => {
    expect(Object.keys(engine).sort()).toEqual([
      "ENDPOINT_URLS",
      "FINDING_IDS",
      "SELECTORS",
      "SEVERITIES",
      "SEVERITY_ORDER",
      "VERDICTS",
      "catalog",
      "catalogEntry",
      "checkAlignment",
      "checkDomain",
      "deliveryRules",
      "fillPlaceholders",
      "fillRua",
      "findingText",
      "fixesAsText",
      "fragmentFor",
      "operators",
      "parseInput",
      "providerList",
      "readFragment",
      "receiverRules",
      "sendingServices",
      "spfLookupDecides",
      "staticText",
      "variantText",
      "verdictRules",
    ]);
  });
});
