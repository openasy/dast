import { describe, expect, it } from "vitest";
import { mask, pageOf, parseSarif, SarifError } from "./sarif.ts";
import { sarif, type TestResult } from "./test-app.ts";

const parse = (tool: string, ...r: TestResult[]) => parseSarif(JSON.parse(sarif(tool, ...r)));
const shop = "https://shop.example.com";

describe("parseSarif", () => {
  it("reads rule, page, parameter, message and evidence", () => {
    const { tool, findings } = parse("ZAP", { rule: "10202", level: "error", url: `${shop}/cart?id=7#top`, param: "id", message: "Absence of anti-CSRF tokens", evidence: "<form action=/cart>" });
    expect(tool).toBe("ZAP");
    expect(findings).toMatchObject([{ fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/), ruleId: "10202", severity: "high", url: `${shop}/cart`, param: "id", message: "Absence of anti-CSRF tokens", evidence: "<form action=/cart>" }]);
  });

  it("takes severity from security-severity first, then from the level", () => {
    const sev = (r: Omit<TestResult, "url">) => parse("zap", { ...r, url: shop }).findings[0]!.severity;
    expect(sev({ rule: "a", score: 9.8 })).toBe("critical");
    expect(sev({ rule: "a", score: 7.5, level: "note" })).toBe("high");
    expect(sev({ rule: "a", score: 5 })).toBe("medium");
    expect(sev({ rule: "a", score: 2 })).toBe("low");
    expect(sev({ rule: "a", level: "error" })).toBe("high");
    expect(sev({ rule: "a" })).toBe("medium");
    expect(sev({ rule: "a", level: "note" })).toBe("low");
  });

  it("follows a finding across scans by rule, page and parameter, not by query string", () => {
    const fp = (url: string, param?: string, rule = "r") => parse("zap", { rule, url, param }).findings[0]!.fingerprint;
    expect(fp(`${shop}/search?q=1`, "q")).toBe(fp(`${shop}/search?q=2`, "q"));
    expect(fp(`${shop}/search`, "q")).not.toBe(fp(`${shop}/search`, "page"));
    expect(fp(`${shop}/search`, "q")).not.toBe(fp(`${shop}/other`, "q"));
    expect(fp(`${shop}/search`, "q")).not.toBe(fp(`${shop}/search`, "q", "other"));
    expect(parse("zap", { rule: "r", url: `${shop}/a` }, { rule: "r", url: `${shop}/a?x=1` }).findings).toHaveLength(1);
  });

  it("leaves out results that are suppressed or have no web address, and says how many", () => {
    const log = JSON.parse(sarif("nuclei", { rule: "a", url: shop }, { rule: "b", url: "src/app.js" }, { rule: "c", url: shop + "/c" }));
    log.runs[0].results[2].suppressions = [{ kind: "external" }];
    const { findings, skipped } = parseSarif(log);
    expect(findings.map((f) => f.ruleId)).toEqual(["a"]);
    expect(skipped).toBe(1);
  });

  it("masks credentials in evidence", () => {
    const evidence = parse("zap", { rule: "r", url: shop, evidence: "Authorization: Bearer abcdefghijklmnop\nCookie: sid=1\npassword=hunter2&x=1" }).findings[0]!.evidence!;
    expect(evidence).not.toMatch(/abcdefghijklmnop|sid=1|hunter2/);
    expect(evidence).toContain("password=***&x=1");
  });

  it("refuses what is not SARIF 2.1", () => {
    expect(() => parseSarif([])).toThrow(SarifError);
    expect(() => parseSarif({ hello: 1 })).toThrow(SarifError);
    expect(() => parseSarif({ version: "1.0.0", runs: [] })).toThrow(/not supported/);
    expect(parseSarif({ version: "2.1.0", runs: [] })).toEqual({ tool: "unknown", findings: [], skipped: 0 });
  });
});

describe("pageOf and mask", () => {
  it("keeps only the page", () => {
    expect(pageOf("https://u:p@shop.example.com/a/b?x=1#y")?.href).toBe("https://shop.example.com/a/b");
    expect(pageOf("ftp://x/")).toBeNull();
    expect(pageOf("not a url")).toBeNull();
  });
  it("hides tokens", () => {
    expect(mask("token=abc123 and x")).toBe("token=*** and x");
  });
});
