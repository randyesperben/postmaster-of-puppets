// The lines that go with a fix in the plain text of every fix (fixesAsText, fixes.ts), in one
// place so any other text of a fix can use the same words. {n} is the step and {o} the number of
// steps.
export const HOST_HINT = "Most DNS panels want the host. If yours adds the domain after the field, use the host.";
// When the SOA gave no zone apex, the host is the full name (fixes.ts, hostFor).
export const HOST_HINT_NO_ZONE =
  "This check could not tell which domain your DNS panel manages, so the host is the full name. If your panel adds your domain after the field, type only the part before your domain.";
export const STEP_FIRST = "Step 1 of {o}. This record starts reports. It does not stop forged mail yet.";
export const STEP = "Step {n} of {o}.";
export const STEP_SUBDOMAINS =
  "Step 1 of {o}. Receivers are now asked to quarantine mail from subdomains that fails DMARC. Your reports show which subdomains send mail: check them before step 2.";
