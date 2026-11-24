// The evaluation a receiver makes for a forger's address, once per address family, and the
// address ranges it reasons about: unions of ip4 or ip6 terms that cover a whole family, and the
// cloud blocks anyone can rent. spf.ts runs it through spf-walk.ts.
import { parseIpv4, parseIpv6, WIDE_PREFIX } from "../ip.ts";
import type { FindingId, SpfNode } from "../types.ts";
import type { Term } from "./spf-terms.ts";

/**
 * Cloud blocks as the generated table writes them, [gap, span, ...] per family
 * (data/cloud-ranges.ts).
 */
export interface CloudTable {
  v4: readonly number[];
  v6: readonly number[];
}

/** Block runs [first, last, ...] per family, from a table of deltas. */
export type CloudRuns = [number[], number[]];

function decode(deltas: readonly number[]): number[] {
  const out: number[] = [];
  let prev = 0;
  for (let i = 0; i + 1 < deltas.length; i += 2) {
    const first = prev + (deltas[i] as number);
    prev = first + (deltas[i + 1] as number);
    out.push(first, prev);
  }
  return out;
}

/** The cloud table decoded into block runs [first, last, ...], IPv4 then IPv6. */
export function runsOf(t: CloudTable): CloudRuns {
  return [decode(t.v4), decode(t.v6)];
}

// ---- The forger's evaluation, per address family (0 = IPv4, 1 = IPv6) ----

export type Family = 0 | 1;
export const FAMILIES: readonly Family[] = [0, 1];
type Result = "pass" | "fail" | "softfail" | "neutral" | "error";
export const RESULT: Record<Term["qualifier"], Result> = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };

/** The term that lets any address pass, to report once the pass reaches the checked domain. */
export interface Cause {
  node: SpfNode;
  pos: number[];
  id: FindingId;
  found: string;
  via: string;
  /** "cloud": a wide range that takes in addresses anyone can rent. */
  reason?: "cloud";
}

interface Outcome {
  result: Result;
  cause?: Cause;
}

/** One record being walked. */
export interface Frame {
  /** Whether the forger's evaluation for each family reaches this record. */
  live: [boolean, boolean];
  /** How that evaluation ended in this record, once it has. */
  out: [Outcome | undefined, Outcome | undefined];
  /**
   * Whether a match here passes the checked domain: every include above is + (redirect keeps it).
   */
  pass: boolean;
  /**
   * Address ranges that an earlier term of this record, or of the records above it, already
   * matches with a result other than pass, per family: the forger's address cannot be there.
   */
  blocked: [Span[], Span[]];
}

export interface Span {
  lo: bigint;
  hi: bigint;
}

/** Whether the forger's evaluation for family `f` reaches this record and has not ended in it. */
export function isRunning(frame: Frame, f: Family): boolean {
  return frame.live[f] && frame.out[f] === undefined;
}

/** Ends the evaluation of these families, the ones still running, with `outcome`. */
export function endWith(frame: Frame, families: readonly Family[], outcome: Outcome): void {
  for (const f of families) if (isRunning(frame, f)) frame.out[f] = outcome;
}

/** A permerror (or a lookup past the limit) ends the evaluation of every family still running. */
export function endWithError(frame: Frame): void {
  endWith(frame, FAMILIES, { result: "error" });
}

/** A term that matches every address of these families. */
export function matchAll(frame: Frame, families: readonly Family[], q: Term["qualifier"], cause: Cause): void {
  endWith(frame, families, q === "+" ? { result: "pass", cause } : { result: RESULT[q] });
}

// ---- Address ranges, for unions of ip4 or ip6 terms that cover a whole family ----

export interface Range extends Span {
  prefix: number;
  cause: Cause;
}

/** The bits of an address, IPv4 then IPv6. */
export const ADDRESS_BITS = [32, 128] as const;

export function rangeOf(f: Family, value: string, prefix: number): { lo: bigint; hi: bigint } {
  const parts = f === 0 ? (parseIpv4(value) ?? []) : (parseIpv6(value) ?? []);
  const width = BigInt(f === 0 ? 8 : 16);
  const addr = parts.reduce((n, p) => (n << width) | BigInt(p), 0n);
  const host = BigInt(ADDRESS_BITS[f] - prefix);
  const lo = (addr >> host) << host;
  return { lo, hi: lo + (1n << host) - 1n };
}

export function covers(f: Family, ranges: Range[]): boolean {
  let next = 0n;
  for (const r of [...ranges].sort((a, b) => (a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0))) {
    if (r.lo > next) return false;
    if (r.hi + 1n > next) next = r.hi + 1n;
  }
  return next === 1n << BigInt(ADDRESS_BITS[f]);
}

/**
 * Whether a range holds a cloud block the forger can still use: a block of the table inside the
 * range that no earlier non-pass term touches. A block touched only in part counts as blocked,
 * so the check errs toward “not open”.
 */
export function reachesCloud(f: Family, span: Span, runs: CloudRuns, blocked: Span[]): boolean {
  const shift = BigInt(ADDRESS_BITS[f] - WIDE_PREFIX[f]);
  const lo = Number(span.lo >> shift);
  const hi = Number(span.hi >> shift);
  const table = runs[f];
  for (let i = 0; i + 1 < table.length; i += 2) {
    const from = Math.max(lo, table[i] as number);
    const to = Math.min(hi, table[i + 1] as number);
    for (let b = from; b <= to; b++) {
      const bLo = BigInt(b) << shift;
      const bHi = bLo + (1n << shift) - 1n;
      if (!blocked.some((x) => x.lo <= bHi && x.hi >= bLo)) return true;
    }
  }
  return false;
}

/** The widest ranges that together still cover the family, in the order they are evaluated. */
export function coveringSet(f: Family, ranges: Range[]): Range[] {
  const kept: Range[] = [];
  for (const r of [...ranges].sort((a, b) => a.prefix - b.prefix)) {
    kept.push(r);
    if (covers(f, kept)) break;
  }
  return ranges.filter((r) => kept.includes(r));
}
