# Contributing

## Prerequisites

- Node.js 22
- The Adversary CLI

## Setup and validation

```sh
npm ci
npm test
doomer validate .
doomer pack --check .
```

`npm test` builds the runtime before running the test suite.

## Adding or changing a check

1. Keep the detector deterministic and evidence-backed; parse repository files
   without executing target code.
2. Update the rule definition in `src/spec.ts` and its runtime behavior when
   needed.
3. Add focused vulnerable and clean fixtures.
4. Add tests covering detection, non-detection, evidence, and ordering.
5. Update the compact detector inventory in `CHECKS.md`.

