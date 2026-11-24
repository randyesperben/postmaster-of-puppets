// The findings of a result as the tests compare them: their ids, or their ids with their severity.
type Findings = { findings: readonly { id: string; severity: string }[] };

export const ids = (r: { findings: readonly { id: string }[] }) => r.findings.map((f) => f.id);
export const idsWithSeverity = (r: Findings) => r.findings.map((f) => `${f.id}:${f.severity}`);
