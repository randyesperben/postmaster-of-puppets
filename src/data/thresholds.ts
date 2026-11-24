// The volume thresholds of Gmail's and Outlook.com's rules for bulk senders, as the engine's texts
// quote them (catalog/spf.ts and receivers.ts). One copy, so every text that quotes a threshold
// gives the same figure.
export const GMAIL_REQUIREMENTS_THRESHOLD = "more than 5,000 messages a day";
export const OUTLOOK_BULK_THRESHOLD = "5,000 or more messages";
