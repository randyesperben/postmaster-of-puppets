# Contributing

## Start with an issue

Most changes start as an issue, and each common case has a form:

- **Email provider**: a provider that is missing, or one whose records are wrong.
- **badmail.dev case**: a broken email setup that the test zone does not have yet.
- **Wrong verdict**: a result that does not match what the standards say.

[Open an issue](https://github.com/randyesperben/postmaster-of-puppets/issues/new/choose) and pick the form.

## Sources

Every rule and every provider record comes from a primary source: an RFC section, or the provider's own documentation. Link it in the issue or the pull request. A record seen on a single domain shows what one owner did, so it cannot be the source on its own.

Each value in `src/providers.ts` has its source in `data/sources/`: the page that states it, the words quoted from it and the day it was read, or the domains whose DNS shows it. A new or changed value needs its entry there.

## Layout

- `src/`: the engine. `src/index.ts` is what the package exports.
  - `src/check.ts`: one full check of a domain, from the first lookup to the verdict and the fixes.
  - `src/checks/`: one check per group of records (MX, SPF, DKIM, DMARC, and MTA-STS with TLS-RPT), with the modules that read each record.
  - `src/catalog/`: every finding a check can give, with its severity, texts, fix and sources.
  - `src/rules.ts` and `src/verdict.ts`: the rules of the verdict, in order, and the code that applies them.
  - `src/fixes.ts` and `src/fixes-dmarc.ts`: the records a report proposes.
  - `src/providers.ts`: email providers, their records and DKIM selectors, and how a domain's records name them.
  - `src/psl.ts`: the Public Suffix List, loaded on demand, for the RFC 7489 reading of DMARC and the MX check.
  - `src/dns/`: the DNS-over-HTTPS client with its endpoints and the check's time limit, the DNS message codec and the helpers for domain names, and the types of a DNS answer and of a resolver.
  - `src/data/`: tables built from public lists (the Public Suffix List, cloud address ranges), and in `thresholds.ts` the volume thresholds of Gmail's and Outlook.com's rules for bulk senders, written by hand.
  - Names of exported constants: a table of records, or a map of them, is in camelCase (`catalog`, `providerList`, `verdictRules`, `operators`), and so is a function; any other fixed value, a list of ids, a map of plain values or a single string or record, is in UPPER_SNAKE_CASE (`FINDING_IDS`, `SEVERITIES`, `SEVERITY_ORDER`, `SELECTORS`, `HOST_HINT`).
- `test/`: the tests, with their helpers in `test/helpers/` and recorded DNS answers and fixed RSA public keys in `test/fixtures/`.
- `data/`: the provider dataset as JSON, with its JSON Schema.
  - `data/sources/`: the source of each provider value, which the dataset is built from. The engine never imports it, so it stays out of the package.

The generated files (the files in `src/data/` that say so in their first lines, the recorded answers and the JSON files of `data/`) are regenerated in the source of postmasterofpuppets.com and arrive with the next export. The two Public Suffix List tables, `src/data/psd-dmarc.ts` and `src/data/psl-rest.ts`, are one list split in two, so they are always rebuilt together, in one step, from the same copy of the list, which both headers name.

## Tests

```sh
npm install
npm test
```

`npm test` checks the formatting with Prettier, type-checks the code and runs the tests; `npm run format` fixes the formatting. To run one file while you work on it:

```sh
npx vitest run test/spf.test.ts
```

A test's title fits in 120 columns, the width Prettier formats to, with any further detail in a comment above it; `test-titles.test.ts` checks it. A comment fits in 100 characters, which Prettier does not wrap; `comment-width.test.ts` checks it, leaving out the generated files.

A new case describes the DNS it needs as a zone, a plain object of names and their records on example.com, example.net or example.org (`test/helpers/zone.ts`), as the cases in `test/spf.test.ts` do.

### Where each module is tested

A module's own tests are in `test/<module>.test.ts`, or in `test/<module>-<topic>.test.ts` when there are many. Tests named `check-<topic>.test.ts` run full checks on a topic: `checkDomain` over a zone, often with each fix applied back to the zone.

| Module                                                                         | Tests                                                                                                                                                                                          |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/check.ts`, `src/index.ts`                                                 | `check.test.ts`, `index.test.ts`, and the `check-*.test.ts` scenarios                                                                                                                          |
| `src/input.ts`, `src/fragment.ts`                                              | `input.test.ts`                                                                                                                                                                                |
| `src/alignment.ts`                                                             | `alignment.test.ts`                                                                                                                                                                            |
| `src/checks/mx.ts`                                                             | `mx.test.ts`                                                                                                                                                                                   |
| `src/checks/spf.ts` and the `spf-` modules beside it                           | `spf.test.ts`, `spf-open.test.ts`, `spf-walk.test.ts`, `check-spf-org.test.ts`                                                                                                                 |
| `src/checks/dkim.ts`                                                           | `dkim.test.ts`, `dkim-signal.test.ts`, `dkim-rotation.test.ts`, `check-dkim.test.ts`                                                                                                           |
| `src/checks/dmarc.ts` and the `dmarc-` modules beside it                       | `dmarc.test.ts`, `dmarc-policy.test.ts`, `dmarc-findings.test.ts`, `dmarc-readings.test.ts`, `dmarc-subdomains.test.ts`, `check-readings.test.ts`                                              |
| `src/checks/transport.ts`                                                      | `transport.test.ts`                                                                                                                                                                            |
| `src/catalog/`                                                                 | `catalog.test.ts`, `check-variants.test.ts`                                                                                                                                                    |
| `src/finding-text.ts`                                                          | `dmarc-findings.test.ts`, `check-existence.test.ts`                                                                                                                                            |
| `src/static-text.ts`                                                           | `static-text.test.ts`                                                                                                                                                                          |
| `src/rules.ts`                                                                 | `rules.test.ts`                                                                                                                                                                                |
| `src/verdict.ts`, `src/findings.ts`                                            | `verdict.test.ts`                                                                                                                                                                              |
| `src/simulate.ts`                                                              | `simulate.test.ts`                                                                                                                                                                             |
| `src/fixes.ts`, `src/fixes-dmarc.ts`, `src/fixes-common.ts`, `src/fix-text.ts` | `fixes.test.ts`, `check-fixes.test.ts`, `check-fixes-dmarc.test.ts`, `check-fixes-dmarc-levels.test.ts`, `check-fixes-spf.test.ts`, `check-fixes-after.test.ts`, `check-fixes-records.test.ts` |
| `src/providers.ts`                                                             | `providers.test.ts`, `check-provider-table.test.ts`, `check-providers.test.ts`                                                                                                                 |
| `data/sources/`                                                                | `sources.test.ts`                                                                                                                                                                              |
| `src/receivers.ts`                                                             | `receivers.test.ts`                                                                                                                                                                            |
| `src/operators.ts`                                                             | `operators.test.ts`                                                                                                                                                                            |
| `src/ip.ts`                                                                    | `ip.test.ts`                                                                                                                                                                                   |
| `src/psl.ts`                                                                   | `psl.test.ts`, and through the checks that load it: `dmarc-readings.test.ts`, `dmarc-subdomains.test.ts`, `mx.test.ts`, `check-readings.test.ts`, `check-limits.test.ts`                       |
| `src/dns/codec.ts`, `src/dns/names.ts`                                         | `codec.test.ts`                                                                                                                                                                                |
| `src/dns/doh.ts`, `src/dns/endpoints.ts`, `src/dns/deadline.ts`                | `doh.test.ts`, `doh-limits.test.ts`, `deadline.test.ts`, `check-crosscheck.test.ts`, `check-deadline.test.ts`, `check-limits.test.ts`                                                          |
| `src/dns/lookup.ts`                                                            | `lookup.test.ts`                                                                                                                                                                               |
| `src/dns/compare.ts`                                                           | `compare.test.ts`                                                                                                                                                                              |
| The whole engine                                                               | `purity.test.ts`: no imports from outside `src/`, no DOM and no Node modules                                                                                                                   |

The modules that hold only types (`src/types.ts`, `src/dns/types.ts` and `src/finding-vars.ts`) and the tables of `src/data/` have no tests of their own: the tests above read the tables through the modules that use them.

### Recorded answers

`test/fixtures/dns/` holds the answers public resolvers gave for a few real domains (google.com, microsoft.com, github.com and others) on 2026-11-18 and 2026-11-19, so some tests read real records without a network. Each file is one DNS message, named `<name>/<TYPE>.bin`, with suffixes before `.bin` for how it was asked and who answered: `.cd` with checking disabled, `.do` with the DNSSEC OK bit, and `.google`, `.quad9`, `.controld`, `.cznic` or `.dns4eu` for that operator. A file without an operator suffix is Cloudflare's answer. The recordings hold 31 DKIM selectors, 29 of them still among the 76 the check tries; a test that replays them answers the others empty or lets their lookups fail, and says which. Folders such as `google.com.google.com` are not mistakes: they answer the lookup for a record name written twice (the `record-name-doubled` finding). `test/fixtures/filtered/` holds what filtering resolvers answered for names they block, and the unfiltered Cloudflare answer they are compared with, named `<resolver host>.<name>.<TYPE>.bin`.

The recordings stay as they are here: they are made in the source of postmasterofpuppets.com, which keeps the recorder.

## Pull requests

This repository is exported in one direction from the source of postmasterofpuppets.com. A pull request is applied to that source by hand, credited to its author with a `Co-authored-by` line, and comes back here with the next export. The pull request is then closed with a link to the commit.

## Code of conduct and security

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md). Report a vulnerability privately, as [SECURITY.md](SECURITY.md) explains.
