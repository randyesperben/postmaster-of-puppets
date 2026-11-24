// The engine's public surface: the one module to import.
export { parseInput } from "./input.ts";
export { fragmentFor, readFragment } from "./fragment.ts";
export { checkDomain } from "./check.ts";
export { fillRua, fixesAsText } from "./fixes.ts";
export { catalog, catalogEntry } from "./catalog/index.ts";
export { staticText } from "./static-text.ts";
export { fillPlaceholders, findingText, variantText } from "./finding-text.ts";
export { SEVERITY_ORDER } from "./findings.ts";
export { verdictRules, deliveryRules } from "./rules.ts";
export { providerList, SELECTORS, sendingServices } from "./providers.ts";
export { operators } from "./operators.ts";
export { ENDPOINT_URLS } from "./dns/endpoints.ts";
export { receiverRules } from "./receivers.ts";
export { checkAlignment } from "./alignment.ts";
export { spfLookupDecides } from "./verdict.ts";

export { FINDING_IDS, SEVERITIES, VERDICTS } from "./types.ts";
export type * from "./types.ts";
export type * from "./finding-vars.ts";
export type * from "./dns/types.ts";
export type { Alignment, AlignmentInput } from "./alignment.ts";
export type { Receiver, ReceiverOutcome, ReceiverRule } from "./receivers.ts";
export type { Rule } from "./rules.ts";
export type { Operator } from "./operators.ts";
export type { StaticText } from "./static-text.ts";
