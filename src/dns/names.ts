// Domain names in presentation form (RFC 1035 §5.1): parsing into labels, the lower case DNS
// compares in (RFC 4343), whether one name is at or below another, and the length limits. No
// imports, so input.ts can take its limits from here and keep its own imports to this file.

/** RFC 1035 §2.3.4: a label holds at most 63 octets. */
export const MAX_LABEL = 63;
/** RFC 1035 §2.3.4: a name holds at most 255 octets on the wire. */
export const MAX_WIRE_NAME = 255;
/** The same limit as text without the final dot: 253 characters. */
export const MAX_NAME = MAX_WIRE_NAME - 2;

/**
 * Lower case for A-Z only (RFC 4343 §3: other octets are not letters), no final dot; the root is
 * ".". Cheap and never throws; canonicalName() gives the exact form.
 */
export function normalizeName(name: string): string {
  const n = name.replace(/[A-Z]+/g, (s) => s.toLowerCase()).replace(/(^|[^\\])((?:\\\\)*)\.$/, "$1$2");
  return n === "" ? "." : n;
}

/** Whether `name` (any case) is `zone` (lower case) or below it, at a label boundary. */
export function isAtOrBelow(name: string, zone: string): boolean {
  const n = name.toLowerCase();
  return n === zone || n.endsWith(`.${zone}`);
}

/**
 * Presentation form (RFC 1035 §5.1) to labels of octets: unescaped dots split labels, \DDD and \X
 * stand for one octet, A-Z are lower-cased. Throws RangeError for a name DNS cannot carry.
 */
export function parseName(name: string): number[][] {
  if (name === "" || name === ".") return [];
  const labels: number[][] = [[]];
  for (let i = 0; i < name.length; i++) {
    const label = labels[labels.length - 1] as number[];
    let c = name.charCodeAt(i);
    if (c === 0x2e) {
      if (i < name.length - 1) labels.push([]);
      continue;
    }
    if (c === 0x5c) {
      const ddd = /^\d{3}/.exec(name.slice(i + 1));
      if (ddd) {
        c = Number(ddd[0]);
        i += 3;
      } else {
        c = name.charCodeAt(++i);
        if (Number.isNaN(c)) throw new RangeError(`escape at the end of ${name}`);
      }
      if (c > 255) throw new RangeError(`escape out of range in ${name}`);
    } else if (c > 127) {
      throw new RangeError(`non-ASCII name ${name}`);
    }
    label.push(c >= 0x41 && c <= 0x5a ? c + 0x20 : c);
  }
  let length = 1;
  for (const label of labels) {
    if (label.length < 1 || label.length > MAX_LABEL) throw new RangeError(`bad label in ${name}`);
    length += label.length + 1;
  }
  if (length > MAX_WIRE_NAME) throw new RangeError(`name too long: ${name}`);
  return labels;
}

/** One label in presentation form: A-Z lower-cased; dot, backslash and non-printables as \DDD. */
export function presentLabel(octets: Uint8Array | number[]): string {
  let s = "";
  for (const b of octets) {
    if (b >= 0x41 && b <= 0x5a) s += String.fromCharCode(b + 0x20);
    else if (b <= 0x20 || b >= 0x7f || b === 0x2e || b === 0x5c) s += `\\${String(b).padStart(3, "0")}`;
    else s += String.fromCharCode(b);
  }
  return s;
}

/** The form decodeMessage gives names in, so any spelling compares equal; throws RangeError. */
export function canonicalName(name: string): string {
  const labels = parseName(name);
  return labels.length === 0 ? "." : labels.map(presentLabel).join(".");
}
