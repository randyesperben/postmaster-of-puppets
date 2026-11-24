// Reads and writes a domain in a URL's fragment (#example.com), which browsers never send to the
// server. A fragment with a dot is taken for a domain; one without a dot is an ordinary anchor,
// such as a finding id, which never contains a dot.

/**
 * The text in a link's fragment ("#example.com"), percent-decoded and trimmed, to pass to
 * parseInput; undefined for a fragment without a dot (an ordinary anchor) or one that does not
 * decode.
 */
export function readFragment(hash: string): string | undefined {
  let value = hash.replace(/^#/, "");
  try {
    value = decodeURIComponent(value);
  } catch {
    return undefined;
  }
  value = value.trim();
  return value.includes(".") ? value : undefined;
}

/** The fragment of a link to a domain's result: "#" and the domain, percent-encoded. */
export function fragmentFor(domain: string): string {
  return `#${encodeURIComponent(domain)}`;
}
