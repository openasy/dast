# dast

[![CI](https://github.com/openasy/dast/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/dast/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) DAST product: what scanners find in **running applications**, kept per
target, with decisions that last (ADR 0037). Your pipeline runs [ZAP](https://www.zaproxy.org/) or
[Nuclei](https://github.com/projectdiscovery/nuclei) against an application you own and sends the
[SARIF](https://sarifweb.azurewebsites.net/) report here. dast tells what is new, what is fixed, and whether the
check passes.

```
CI: nuclei -u https://shop.example.com -se results.sarif  ──POST /api/v1/scans──▶  dast  ──▶  { new, resolved, blocking, passed }
                                                                                   └── targets, findings, triage, history
```

[dast-agent](https://github.com/openasy/dast-agent) runs ZAP and Nuclei for you, inside your network: start a scan on
a target's page or give the target a schedule. dast itself holds no scanner and attacks nothing.

## Scans by the agent

- **Profiles.** `passive` crawls and watches, with no attacks. `standard` adds ZAP's active rules at low strength and
  Nuclei's templates that are not intrusive. `full` runs every rule of both. A target that is not verified gets only
  passive scans; a full scan of a production target needs an admin.
- **Schedules.** Daily or weekly per target, with the profile to run; the scan is limited to what the target allows
  when it runs.
- **One report per engine and profile**, such as `zap-standard` or `nuclei-full`, so a passive scan never marks what an
  active one found as fixed.
- **Logins** let a scan get past the target's sign-in page: a header sent with every request, or a form ZAP fills in.
  The secret is sealed with `openasy-kek`, never sent back, and given only to the agent running a scan that uses it.
  Nuclei uses a header login and runs signed out with a form login. A form must be sent to the target's own origin.
- **Agents** enrol with a one-time token from Agents and ask for jobs; a job an agent does not finish within 3 hours goes
  back to the queue, three times at most. A target on a private address is verified by an agent in its network.

## Targets

A **target** is an address that may be tested, such as `https://shop.example.com`, or with a path to test only a part of
it. Reports are accepted only for targets that exist, and results outside a target's address are left out and counted.

The owner of an address **proves it is theirs**: serve the text dast shows, on its own, at
`/.well-known/openasy-dast` of the target, then choose Verify. dast fetches it over the public internet, without
following redirects, and refuses addresses on private networks (an agent in that network will verify those). Reports
are accepted before verification, since importing one attacks nothing; the scans dast will run itself never start on a
target that is not verified, and never run in full on one marked production without an admin's say.

## How a report is compared

- A report belongs to an **engine** (`zap`, `nuclei`, or the `engine` you send). Its reports replace each other:
  what it stops reporting is marked fixed, and opens again if it returns. Engines do not fix each other's findings.
- The **first report** of an engine for a target adopts what is there and never fails a check. Later reports fail it
  for **new** findings at or above the target's **fail on** severity (high by default; set under the target) that
  nobody has triaged.
- A finding is found again by **rule, page and parameter**, not by its query string.
- A **false positive** or **accepted risk** (with a reason, and an end date for accepted risk) stays with the finding.
- Passwords, cookies and tokens in what an engine saw are **masked** before anything is stored.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export DAST_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs dast | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

Add a target in the UI, verify it, then send a report from CI:

```bash
nuclei -u https://shop.example.com -se results.sarif
curl -sf -X POST -H "Authorization: Bearer $DAST_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif "https://dast.example.com/api/v1/scans?target=shop-staging" > scan.json
jq -e '.passed' scan.json
```

The body may be gzipped (`Content-Encoding: gzip`), up to 64 MiB unpacked and 20,000 results.

`openasy-kek` encrypts sign-in secrets in dast's database (ADR 0021). Keep it apart from the volume and with your
backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `DAST_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `DAST_INGEST_TOKEN` | | Lets CI send reports and nothing else. An API token with the editor role works too |
| `DAST_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `DAST_DB` | `/data/dast.db` | SQLite file (WAL), on the `/data` volume |
| `DAST_RETENTION_DAYS` | `365` | Reports, and fixed findings nobody triaged, older than this are deleted |
| `DAST_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `DAST_HEADLESS` | `false` | `true` serves only the API |
| `DAST_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)). Owners can also add identity providers under Settings, Sign-in |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

Findings hold what a scanner saw, which can include personal data. Anyone with the viewer role reads it, and deleting a
target deletes it.

## Roles

Viewers see everything; editors also triage findings and send reports; admins also add, verify, change and delete
targets, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # SARIF parsing, comparison with earlier reports, triage, verification, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
