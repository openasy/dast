import { describe, expect, it } from "vitest";
import { fetchProof, isPrivate } from "./verify.ts";

describe("isPrivate", () => {
  it("knows addresses dast must not be turned on", () => {
    for (const a of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "224.0.0.1"]) expect(isPrivate(a), a).toBe(true);
    for (const a of ["8.8.8.8", "172.32.0.1", "93.184.216.34", "2606:4700:4700::1111"]) expect(isPrivate(a), a).toBe(false);
  });
});

describe("fetchProof", () => {
  it("refuses private addresses without connecting", async () => {
    await expect(fetchProof("http://127.0.0.1:9")).rejects.toThrow(/private address/);
    await expect(fetchProof("http://169.254.169.254")).rejects.toThrow(/private address/);
    await expect(fetchProof("http://localhost")).rejects.toThrow(/private address/);
  });
});
