import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** Where the owner of an address proves it (ADR 0037). */
export const VERIFY_PATH = "/.well-known/openasy-dast";

/** Fetches the proof from a target's origin. Returns its text, or throws with what went wrong. */
export type Verifier = (origin: string) => Promise<string>;

/** Addresses a target may not resolve to: dast fetches the proof itself, so it must not be turned on its own network. */
export function isPrivate(address: string): boolean {
  const a = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (a.startsWith("::ffff:")) return isPrivate(a.slice(7));
  if (isIP(a) === 4) {
    const [p, q] = a.split(".").map(Number) as [number, number];
    return p === 0 || p === 10 || p === 127 || (p === 100 && q >= 64 && q <= 127) || (p === 169 && q === 254) || (p === 172 && q >= 16 && q <= 31) || (p === 192 && q === 168) || (p === 192 && q === 0) || p >= 224;
  }
  return a === "::" || a === "::1" || a.startsWith("fc") || a.startsWith("fd") || /^fe[89ab]/.test(a);
}

/**
 * The default proof: a GET of /.well-known/openasy-dast over the public internet, without redirects. The answer is
 * only compared with a secret that was never shown to the target, so the fetch tells a caller nothing but yes or no.
 * Targets on private addresses are verified by the agent that can reach them (ADR 0037).
 */
export const fetchProof: Verifier = async (origin) => {
  const url = new URL(VERIFY_PATH, origin);
  const addresses = isIP(url.hostname) ? [{ address: url.hostname }] : await lookup(url.hostname, { all: true }).catch(() => []);
  if (!addresses.length) throw new Error(`${url.hostname} does not resolve.`);
  if (addresses.some((a) => isPrivate(a.address))) throw new Error(`${url.hostname} is on a private address; an agent in that network verifies it.`);
  const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000), headers: { accept: "text/plain" } });
  if (res.status !== 200) throw new Error(`${url.href} answered ${res.status}.`);
  return (await res.text()).slice(0, 256);
};
