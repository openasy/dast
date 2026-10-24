import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseEndpoints } from "./endpoints.ts";

// The same file as in Uptime and Certificates (ADR 0052): every product reads the same entries.
const FIXTURE = readFileSync(new URL("./testdata/endpoints.yaml", import.meta.url), "utf8");

describe("the endpoints file", () => {
  it("reads the same entries as Uptime and Certificates do", () => {
    expect(parseEndpoints(FIXTURE).map((e) => `${e.name}: ${e.kind} ${e.host}:${e.port} ${e.server ?? "-"}`)).toEqual([
      "Website: http www.example.com:443 web-1",
      "API: http api.example.com:8443 web-1",
      "Mail: tls mail.example.com:465 -",
      "Database: tcp db.example.com:5432 db-1",
      "Resolver: dns example.com:null -",
      "Old site: http old.example.com:80 -",
    ]);
  });

  it("keeps a dast block for DAST to check, and the failures Uptime uses", () => {
    const [e] = parseEndpoints("endpoints:\n  - { name: Shop, url: https://shop.example.com, failures: 3, dast: { schedule: weekly } }");
    expect(e).toMatchObject({ failures: 3, dast: { schedule: "weekly" } });
    expect(() => parseEndpoints("endpoints:\n  - { name: Shop, url: https://shop.example.com, dast: weekly }")).toThrow(/dast is a map/);
    expect(() => parseEndpoints("endpoints:\n  - { name: Shop, url: https://shop.example.com, failures: 0 }")).toThrow(/failures is a whole number/);
  });
});
