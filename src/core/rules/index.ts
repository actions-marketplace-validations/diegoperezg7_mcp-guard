import {
  ambiguousDirective,
  exfiltrationRequest,
  hiddenContent,
  invisibleCharacters,
  modelDirectedInstructions,
} from "./poisoning.js";
import {
  commandArgument,
  destructiveWithoutHint,
  missingAnnotations,
  misleadingReadOnly,
  pathArgument,
  urlArgument,
} from "./permissions.js";
import { environmentLeak, injectionInOutput, secretInOutput } from "./runtime.js";
import { secretInMetadata } from "./secrets.js";
import {
  confusableName,
  crossServerReference,
  mixedScriptName,
  nameCollision,
} from "./shadowing.js";
import {
  exposedWithoutAuth,
  missingRebindingProtection,
  plaintextHttp,
  remoteWithoutAuth,
} from "./transport.js";
import { scanTruncated } from "./coverage.js";
import type { Rule } from "./types.js";

/** Every rule, in id order. docs/rules.md and the SARIF rule table are generated from this list. */
export const RULES: readonly Rule[] = [
  invisibleCharacters,
  modelDirectedInstructions,
  exfiltrationRequest,
  hiddenContent,
  ambiguousDirective,
  nameCollision,
  confusableName,
  mixedScriptName,
  crossServerReference,
  destructiveWithoutHint,
  misleadingReadOnly,
  commandArgument,
  pathArgument,
  urlArgument,
  missingAnnotations,
  secretInMetadata,
  plaintextHttp,
  exposedWithoutAuth,
  missingRebindingProtection,
  remoteWithoutAuth,
  injectionInOutput,
  secretInOutput,
  environmentLeak,
  scanTruncated,
];

export function getRule(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}

export type { Rule, RuleMeta, RuleCategory } from "./types.js";
