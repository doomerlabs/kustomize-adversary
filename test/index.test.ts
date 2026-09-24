import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [
  { key: "literal-secret", id: "kustomize.literal-secret" },
  { key: "mutable-remote", id: "kustomize.mutable-remote" },
  { key: "configmap-secret-shaped", id: "kustomize.configmap-secret-shaped" },
  { key: "patch-privilege-escalation", id: "kustomize.patch-privilege-escalation" },
  { key: "api-version-json-patch", id: "kustomize.api-version-json-patch" },
  { key: "latest-image", id: "kustomize.latest-image" },
  { key: "name-suffix-hash-disabled", id: "kustomize.name-suffix-hash-disabled" },
  { key: "deprecated-patches-strategic-merge", id: "kustomize.deprecated-patches-strategic-merge" },
];

test("every initial rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("explicit default namespace is not a finding by itself", async () => {
  const output = await review("clean/default-namespace");
  assert.deepEqual(output.findings, []);
});

test("deprecated patchesStrategicMerge evidence points to the field", async () => {
  const output = await review("rules/deprecated-patches-strategic-merge/vulnerable", true);
  const observation = output.rawObservations?.find((item) => item.ruleId === "kustomize.deprecated-patches-strategic-merge");
  assert.equal(observation?.location?.line, 7);
  assert.equal(observation?.location?.snippet, "patchesStrategicMerge:");
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "container/kustomize");
});
