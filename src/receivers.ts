// What Gmail, Yahoo Mail, Outlook.com and Microsoft 365 document for an email that fails DMARC, by
// what the record asks. The texts say what each documentation says, never what will happen:
// RFC 9989 §5.4 leaves the final handling to the receiver. Every source was opened on its `checked`
// date. Each label is “publisher, title”, the title being the page's H1 (read 2026-11-20).
import { OUTLOOK_BULK_THRESHOLD } from "./data/thresholds.ts";
import type { Ask, Source } from "./types.ts";

/** The receivers whose documentation receiverRules quotes. */
export type Receiver = "gmail" | "yahoo" | "outlook-com" | "microsoft-365";
/** What a receiver documents for an email that fails DMARC. */
export type ReceiverOutcome = "rejected" | "spam" | "held" | "filters-decide" | "not-documented";
/** A row of receiverRules: what one receiver documents for one request of the policy. */
export interface ReceiverRule {
  receiver: Receiver;
  /** "Gmail", "Yahoo Mail", "Outlook.com", "Microsoft 365". */
  name: string;
  asks: Ask | "no-dmarc";
  outcome: ReceiverOutcome;
  /** One line; with "rejected", the documented code when there is one. */
  detail: string;
  /** The documentation, with the date it was read (YYYY-MM-DD). */
  source: Source & { readonly checked: string };
}

const CHECKED = "2026-11-18";

/**
 * Gmail's rejection when DMARC fails on a domain whose record asks for reject: the first two
 * sentences, as its SMTP error table prints them. receiverRules quotes the first one.
 */
export const GMAIL_DMARC_REJECTION =
  "550 5.7.26 Unauthenticated email from domain-name is not accepted due to domain's DMARC policy. Contact the administrator of domain-name domain if this was legitimate email.";

const GOOGLE_SMTP = {
  label: "Google, Gmail SMTP errors and codes",
  url: "https://knowledge.workspace.google.com/admin/support/troubleshooting/gmail-smtp-errors-and-codes",
  checked: CHECKED,
};
const GOOGLE_DMARC = {
  label: "Google, Set up DMARC",
  url: "https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
  checked: CHECKED,
};
const YAHOO_FAQ = { label: "Yahoo, FAQs", url: "https://senders.yahooinc.com/faqs/", checked: CHECKED };
const YAHOO_SMTP = {
  label: "Yahoo, SMTP Error Codes",
  url: "https://senders.yahooinc.com/smtp-error-codes/",
  checked: "2026-11-19",
};
const OUTLOOK = {
  label: "Microsoft, Announcing New DMARC Policy Handling Defaults for Enhanced Email Security",
  url: "https://techcommunity.microsoft.com/blog/exchange/announcing-new-dmarc-policy-handling-defaults-for-enhanced-email-security/3878883",
  checked: CHECKED,
};
const OUTLOOK_515 = {
  label: "Microsoft, Fix NDR error “550 5.7.515” in Outlook.com",
  url: "https://support.microsoft.com/en-us/outlook/fix-ndr-error-550-5-7-515-in-outlook-com",
  checked: CHECKED,
};
const M365_DMARC = {
  label: "Microsoft, Set up DMARC to validate the From address domain for cloud senders",
  url: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure",
  checked: CHECKED,
};
const M365_SPOOFING = {
  label: "Microsoft, Anti-spoofing protection for cloud mailboxes",
  url: "https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about",
  checked: CHECKED,
};
const M365_DEFAULTS = {
  label: "Microsoft, Recommended email and collaboration threat policy settings for cloud organizations",
  url: "https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365",
  checked: CHECKED,
};

const NAMES: Record<Receiver, string> = {
  gmail: "Gmail",
  yahoo: "Yahoo Mail",
  "outlook-com": "Outlook.com",
  "microsoft-365": "Microsoft 365",
};

// Gmail, Yahoo Mail and Outlook.com document the bulk sender without a record and nothing else
// about a domain without one.
const NO_RECORD_REST = " It does not say what it does with other email from a domain without one.";
// The 2023 announcement is paraphrased: its own words are in the first person, and cutting them
// would leave a sentence Microsoft did not write.
const OUTLOOK_REJECTS =
  "Microsoft says Outlook.com rejects email that fails DMARC when the record asks for quarantine or reject (announcement, July 2023).";

function row(
  receiver: Receiver,
  asks: Ask | "no-dmarc",
  outcome: ReceiverOutcome,
  detail: string,
  source: ReceiverRule["source"],
): ReceiverRule {
  return { receiver, name: NAMES[receiver], asks, outcome, detail, source };
}

/**
 * What Gmail, Yahoo Mail, Outlook.com and Microsoft 365 document for an email that fails DMARC:
 * one row per receiver for each request of the policy and for a domain without a record, with
 * the documentation it comes from. One row per line, so the table reads row by row; Prettier
 * leaves it as written.
 */
// prettier-ignore
export const receiverRules: readonly Readonly<ReceiverRule>[] = [
  // Gmail. Google's own wording, 2026-11-10: 550 5.7.26 in the SMTP error table; quarantine is
  // “Mark the messages as spam and send it to the recipient's spam folder” in Set up DMARC (a
  // description of the policy, not a sentence about Gmail mailboxes).
  row("gmail", "reject", "rejected", GMAIL_DMARC_REJECTION.slice(0, GMAIL_DMARC_REJECTION.indexOf(". ") + 1), GOOGLE_SMTP),
  row("gmail", "quarantine", "spam", "Google describes quarantine as sending the email to the recipient’s spam folder.", GOOGLE_DMARC),
  row("gmail", "nothing", "filters-decide", "Google describes none as taking no action on the email.", GOOGLE_DMARC),
  row("gmail", "no-dmarc", "not-documented", `Google blocks mail from bulk senders without a DMARC record (550 5.7.40).${NO_RECORD_REST}`, GOOGLE_SMTP),

  // Yahoo Mail. Its SMTP error codes page lists a failed DMARC or DKIM check among the causes of
  // the permanent 553 and 554 errors (read 2026-11-19): a cause, not the server's reply, so the row
  // is prose, not a quoted reply. The FAQ covers p=reject only.
  row("yahoo", "reject", "rejected", "Yahoo lists a message that failed authentication checks against the sending domain’s DMARC or DKIM policy among the causes of its permanent 553 and 554 errors.", YAHOO_SMTP),
  row("yahoo", "quarantine", "not-documented", "Its sender FAQ does not say what it does when the record asks for quarantine.", YAHOO_FAQ),
  row("yahoo", "nothing", "not-documented", "Its sender FAQ does not say what it does when the record asks for nothing.", YAHOO_FAQ),
  // The FAQ says what happens to mail that misses the requirements; the requirement itself (bulk
  // senders publish DMARC, at least p=none) is on the best-practices page it links.
  row("yahoo", "no-dmarc", "not-documented", `Yahoo requires a DMARC record from bulk senders and says their mail may go to spam or be rejected without one.${NO_RECORD_REST}`, YAHOO_FAQ),

  // Outlook.com (consumer). Blog post of 2023-07-19, updated 2023-07-26: quarantine and reject are
  // both rejected.
  row("outlook-com", "reject", "rejected", OUTLOOK_REJECTS, OUTLOOK),
  row("outlook-com", "quarantine", "rejected", OUTLOOK_REJECTS, OUTLOOK),
  row("outlook-com", "nothing", "not-documented", "The announcement covers quarantine and reject only.", OUTLOOK),
  row("outlook-com", "no-dmarc", "not-documented", `Microsoft rejects mail from domains that send ${OUTLOOK_BULK_THRESHOLD} to Outlook.com without a DMARC record (550 5.7.515).${NO_RECORD_REST}`, OUTLOOK_515),

  // Microsoft 365 with default settings: “Honor DMARC record policy when the message is detected as
  // spoof” is on, DmarcRejectAction is Reject and DmarcQuarantineAction is Quarantine (recommended
  // settings, 2026-08-10); the DMARC page (2026-07-03) says Junk Email folder for quarantine, so
  // the two pages disagree and the row names both.
  row("microsoft-365", "reject", "rejected", "550 5.7.1, with dmarc=fail action=oreject, when the email is detected as spoofing.", M365_DMARC),
  row("microsoft-365", "quarantine", "held", "Held in quarantine or the Junk Email folder, when the email is detected as spoofing.", M365_DEFAULTS),
  row("microsoft-365", "nothing", "filters-decide", "No DMARC-specific action. Other filtering still applies.", M365_DMARC),
  // Without a record a forged email gets dmarc=none in its Authentication-Results header
  // (Microsoft's message headers page, ms.date 2026-07-27; bestguesspass is only for one that
  // would have passed). M365_SPOOFING documents compauth=fail with reason 000 and 001 as
  // cross-domain spoofing, 001 being the implicit check (ms.date 2026-05-29).
  row("microsoft-365", "no-dmarc", "filters-decide", "No DMARC record. Microsoft’s own check can still mark it as spoofing (compauth=fail, reason 001).", M365_SPOOFING),
];
