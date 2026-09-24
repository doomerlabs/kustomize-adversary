import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; anchors?: MatchExpression[]; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

const KUSTOMIZATION_FILES = [
  "Kustomization",
  "kustomization.yml",
  "kustomization.yaml",
  "**/Kustomization",
  "**/kustomization.yml",
  "**/kustomization.yaml",
] as const;

const YAML_FILES = [
  ...KUSTOMIZATION_FILES,
  "**/*.yaml",
  "**/*.yml",
] as const;

export const spec = {
  "id": "kustomize",
  "displayName": "Kustomize",
  "description": "Reviews Kustomize overlays for mutable resources, image tags, and literal secrets.",
  "files": [...YAML_FILES],
  "rules": [
    {
      "id": "kustomize.literal-secret",
      "title": "Secret generator embeds a credential literal",
      "summary": "Secret generator embeds a credential literal",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "secretGenerator literals and committed credential files become secrets in git history.",
      "impact": "Committed credentials for apps and infrastructure are recoverable from the repo.",
      "recommendation": "Use SOPS-encrypted sources, SealedSecrets, or External Secrets Operator.",
      "complexity": "small",
      "tags": ["secrets", "literal-secret"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": {
          "pattern": "secretGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,160}(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+",
          "flags": "i"
        },
        "anchors": [
          { "pattern": "secretGenerator:", "flags": "i" },
          { "pattern": "(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+", "flags": "i" }
        ],
        "requires": []
      }
    },
    {
      "id": "kustomize.mutable-remote",
      "title": "Remote resource tracks a mutable branch",
      "summary": "Remote resource tracks a mutable branch",
      "category": "supply-chain",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Remote bases pinned to main/master/HEAD let whoever controls the branch control what you apply.",
      "impact": "Supply-chain substitution of entire base manifests without an overlay change.",
      "recommendation": "Pin remote resources to immutable commit SHAs; vendor bases you do not control.",
      "complexity": "small",
      "tags": ["supply-chain", "mutable-remote"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": {
          "pattern": "(?:github\\.com|https?://)[^\\s]+(?:\\?ref=(?:main|master|HEAD)|#(?:main|master|HEAD)\\b)",
          "flags": "i"
        },
        "anchors": [
          { "pattern": "configMapGenerator:", "flags": "i" },
          { "pattern": "(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+", "flags": "i" }
        ],
        "requires": []
      }
    },
    {
      "id": "kustomize.configmap-secret-shaped",
      "title": "ConfigMap generator carries credential-shaped data",
      "summary": "ConfigMap generator carries credential-shaped data",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "ConfigMaps are not secret objects — broader read access and no secret handling.",
      "impact": "Credentials exposed to any subject that can read ConfigMaps in the namespace.",
      "recommendation": "Move credentials to secretGenerator with an encrypted source or external secret manager.",
      "complexity": "small",
      "tags": ["secrets", "configmap"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": {
          "pattern": "configMapGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,160}(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+",
          "flags": "i"
        },
        "anchors": [
          { "pattern": "(?:privileged|hostNetwork|hostPID|hostIPC):\\s*true|hostPath:", "flags": "i" },
          { "pattern": "capabilit(?:y|ies):", "flags": "i" },
          { "pattern": "(?:add\\s*:|SYS_ADMIN)", "flags": "i" }
        ],
        "requires": []
      }
    },
    {
      "id": "kustomize.patch-privilege-escalation",
      "title": "Overlay patch introduces elevated privilege",
      "summary": "Overlay patch introduces elevated privilege",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Patches can quietly add privileged mode, host namespaces, hostPath, or dangerous capabilities.",
      "impact": "Production overlays become host-compromising while the base still looks clean.",
      "recommendation": "Keep privilege visible in the base for review, or remove it; overlays should not raise security posture.",
      "complexity": "small",
      "tags": ["security", "patch", "privilege"],
      "match": {
        "kind": "content",
        "files": ["**/*.yaml", "**/*.yml"],
        "pattern": {
          "pattern": "(?:privileged:\\s*true|hostNetwork:\\s*true|hostPID:\\s*true|hostIPC:\\s*true|hostPath:|capabilit(?:y|ies):[\\s\\S]{0,80}(?:add|SYS_ADMIN))",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kustomize.api-version-json-patch",
      "title": "JSON patch rewrites a resource apiVersion",
      "summary": "JSON patch rewrites a resource apiVersion",
      "category": "reliability",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "apiVersion is part of a Kubernetes resource's identity and schema contract. Rewriting it after generation can leave the object shaped for one API version but submitted as another.",
      "impact": "The rendered object can fail validation, target a different API contract, or conceal that the base itself needs migration.",
      "recommendation": "Update the base or generator to emit the intended apiVersion instead of JSON-patching /apiVersion.",
      "complexity": "small",
      "tags": ["reliability", "patch", "api-version"],
      "match": {
        "kind": "content",
        "files": ["**/*.yaml", "**/*.yml"],
        "pattern": {
          "pattern": "(?:-\\s*op:\\s*(?:add|replace)\\s*(?:#.*)?\\r?\\n\\s*path:\\s*[\\\"']?/apiVersion[\\\"']?\\s*$|-\\s*path:\\s*[\\\"']?/apiVersion[\\\"']?\\s*(?:#.*)?\\r?\\n\\s*op:\\s*(?:add|replace)\\s*$)",
          "flags": "im"
        },
        "anchors": [
          { "pattern": "op:\\s*(?:add|replace)", "flags": "i" },
          { "pattern": "path:\\s*[\\\"']?/apiVersion", "flags": "i" }
        ],
        "requires": []
      }
    },
    {
      "id": "kustomize.latest-image",
      "title": "Image override uses a mutable tag",
      "summary": "Image override uses a mutable tag",
      "category": "supply-chain",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "The images transformer is the deploy-time pin — floating tags make every apply a different deploy.",
      "impact": "Non-reproducible production images and tag-move supply-chain risk.",
      "recommendation": "Use digest overrides for deployed images; version tags at minimum.",
      "complexity": "small",
      "tags": ["supply-chain", "latest-image"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": { "pattern": "newTag:\\s*(?:latest|main|edge)\\b", "flags": "i" },
        "requires": []
      }
    },
    {
      "id": "kustomize.name-suffix-hash-disabled",
      "title": "Generator name-suffix hash is disabled",
      "summary": "Generator name-suffix hash is disabled",
      "category": "reliability",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "The suffix hash is what makes ConfigMap/Secret changes trigger rollouts.",
      "impact": "Pods keep stale config after generator edits until something else restarts them.",
      "recommendation": "Keep the suffix hash; pair fixed names with a config-reloader if required.",
      "complexity": "small",
      "tags": ["reliability", "generator"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": { "pattern": "disableNameSuffixHash:\\s*true", "flags": "i" },
        "requires": []
      }
    },
    {
      "id": "kustomize.deprecated-patches-strategic-merge",
      "title": "Kustomization uses deprecated patchesStrategicMerge",
      "summary": "Kustomization uses deprecated patchesStrategicMerge",
      "category": "hygiene",
      "severity": "low",
      "confidence": "high",
      "whyItMatters": "Kustomize deprecated patchesStrategicMerge in favor of the unified patches API.",
      "impact": "Builds emit deprecation warnings and the overlay becomes harder to carry across Kustomize upgrades.",
      "recommendation": "Move each strategic-merge patch file to a patches entry with a path field.",
      "complexity": "trivial",
      "tags": ["hygiene", "deprecation", "patches"],
      "match": {
        "kind": "content",
        "files": [...KUSTOMIZATION_FILES],
        "pattern": { "pattern": "^patchesStrategicMerge\\s*:", "flags": "m" },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
