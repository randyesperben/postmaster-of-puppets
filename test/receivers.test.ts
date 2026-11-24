import { describe, expect, it } from "vitest";
import { receiverRules } from "../src/receivers.ts";
import type { Receiver } from "../src/receivers.ts";

const RECEIVERS: Receiver[] = ["gmail", "yahoo", "outlook-com", "microsoft-365"];
const ASKS = ["reject", "quarantine", "nothing", "no-dmarc"] as const;

// The receivers table, cell by cell. Without a record, Gmail, Yahoo Mail and Outlook.com sources
// say nothing about what they do: not-documented.
const EXPECTED: Record<Receiver, Record<(typeof ASKS)[number], string>> = {
  gmail: { reject: "rejected", quarantine: "spam", nothing: "filters-decide", "no-dmarc": "not-documented" },
  yahoo: { reject: "rejected", quarantine: "not-documented", nothing: "not-documented", "no-dmarc": "not-documented" },
  "outlook-com": {
    reject: "rejected",
    quarantine: "rejected",
    nothing: "not-documented",
    "no-dmarc": "not-documented",
  },
  "microsoft-365": { reject: "rejected", quarantine: "held", nothing: "filters-decide", "no-dmarc": "filters-decide" },
};

describe("receiverRules", () => {
  it("has exactly one row for each receiver and each thing the record can ask", () => {
    expect(receiverRules).toHaveLength(RECEIVERS.length * ASKS.length);
    for (const receiver of RECEIVERS) {
      for (const asks of ASKS) {
        const rows = receiverRules.filter((r) => r.receiver === receiver && r.asks === asks);
        expect(rows, `${receiver} × ${asks}`).toHaveLength(1);
        expect(rows[0]?.outcome, `${receiver} × ${asks}`).toBe(EXPECTED[receiver][asks]);
      }
    }
  });

  it("names each receiver by its display name", () => {
    const names = Object.fromEntries(receiverRules.map((r) => [r.receiver, r.name]));
    expect(names).toEqual({
      gmail: "Gmail",
      yahoo: "Yahoo Mail",
      "outlook-com": "Outlook.com",
      "microsoft-365": "Microsoft 365",
    });
  });

  it("gives every row an https source with a checked date", () => {
    for (const r of receiverRules) {
      expect(r.source.url, r.source.label).toMatch(/^https:\/\/[^\s/]+\.[^\s/]+\//);
      expect(r.source.label.trim()).not.toBe("");
      expect(r.source.checked).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(Number.isNaN(Date.parse(`${r.source.checked}T00:00:00Z`))).toBe(false);
    }
  });

  it("never says will or we, in any text", () => {
    for (const r of receiverRules) {
      for (const text of [r.name, r.detail, r.source.label]) {
        expect(text, text).not.toMatch(/\bwill\b/i);
        expect(text, text).not.toMatch(/\b(we|we're|we've|we'll|we'd|our|ours)\b/i);
      }
    }
  });

  it("gives the documented code in a rejected row where there is one, and one line of detail everywhere", () => {
    const detail = (receiver: Receiver) =>
      receiverRules.find((r) => r.receiver === receiver && r.asks === "reject")?.detail ?? "";
    expect(detail("gmail")).toMatch(/^550 5\.7\.26 /);
    // Yahoo's page lists the failed check as one cause of 553 and 554, so the row says so in prose
    // and does not read as the server's reply (senders.yahooinc.com/smtp-error-codes/, read
    // 2026-11-19).
    expect(detail("yahoo")).toBe(
      "Yahoo lists a message that failed authentication checks against the sending domain’s DMARC or DKIM policy among the causes of its permanent 553 and 554 errors.",
    );
    expect(detail("microsoft-365")).toMatch(/^550 5\.7\.1,/);
    for (const r of receiverRules) expect(r.detail).toMatch(/^[^\n]+\.$/);
  });

  // The three document the bulk sender without DMARC, so each row names that case from the page
  // that says it and keeps “not documented” for the rest. Read 2026-11-18: Gmail SMTP errors and
  // codes (550 5.7.40), Yahoo Sender Hub FAQs (“may be sent to the spam folder or rejected”),
  // Microsoft Support “550 5.7.515” (5,000 or more messages).
  it("without DMARC, names the documented bulk-sender case from its own page and leaves the rest undocumented", () => {
    const row = (receiver: Receiver) => receiverRules.find((r) => r.receiver === receiver && r.asks === "no-dmarc");
    const rest = " It does not say what it does with other email from a domain without one.";
    expect(row("gmail")?.detail).toBe(
      `Google blocks mail from bulk senders without a DMARC record (550 5.7.40).${rest}`,
    );
    expect(row("gmail")?.source.url).toBe(
      "https://knowledge.workspace.google.com/admin/support/troubleshooting/gmail-smtp-errors-and-codes",
    );
    expect(row("yahoo")?.detail).toBe(
      `Yahoo requires a DMARC record from bulk senders and says their mail may go to spam or be rejected without one.${rest}`,
    );
    expect(row("yahoo")?.source.url).toBe("https://senders.yahooinc.com/faqs/");
    expect(row("outlook-com")?.detail).toBe(
      `Microsoft rejects mail from domains that send 5,000 or more messages to Outlook.com without a DMARC record (550 5.7.515).${rest}`,
    );
    expect(row("outlook-com")?.source.url).toBe(
      "https://support.microsoft.com/en-us/outlook/fix-ndr-error-550-5-7-515-in-outlook-com",
    );
    for (const r of receiverRules)
      expect(r.detail, r.name).not.toMatch(/does not say what it does when the domain has no DMARC record/);
  });

  // bestguesspass is the result of a message that would have passed (Microsoft Learn, “Anti-spam
  // message headers”, ms.date 2026-07-27, read 2026-11-18); a forged one from a domain without a
  // record gets dmarc=none, and compauth=fail with reason 001. “spoofing” is backed by
  // “Anti-spoofing protection” (ms.date 2026-05-29, read 2026-11-18), which ties compauth=fail
  // reason=000/001 to cross-domain spoofing; the headers page names the codes but not spoofing.
  // dmarc=none stays in the simulation's Authentication-Results line.
  it("Microsoft 365 without DMARC: the composite check marks it as spoofing, never bestguesspass", () => {
    const row = receiverRules.find((r) => r.receiver === "microsoft-365" && r.asks === "no-dmarc");
    expect(row?.detail).toBe(
      "No DMARC record. Microsoft’s own check can still mark it as spoofing (compauth=fail, reason 001).",
    );
    expect(row?.detail).not.toMatch(/bestguesspass/);
    expect(row?.source.url).toBe(
      "https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about",
    );
  });
});
