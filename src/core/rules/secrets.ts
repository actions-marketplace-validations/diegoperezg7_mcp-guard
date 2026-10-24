import { findSecrets } from "../secrets.js";
import { textFields } from "../text.js";
import { defineRule, REF } from "./types.js";

export const secretInMetadata = defineRule(
  {
    id: "MCPG-030",
    name: "SecretInMetadata",
    title: "Credential embedded in tool, resource or prompt metadata",
    category: "secrets",
    severity: "critical",
    mode: "static",
    description:
      "A string that matches a known credential format (cloud keys, GitHub, Slack and Stripe tokens, LLM provider keys, private keys, JWTs, passwords in URLs) appears in metadata that every connected client downloads and forwards to the model. Treat it as leaked.",
    remediation:
      "Revoke and rotate the credential first, then remove it from the server. Load secrets from the environment or a secret manager on the server side; never put them in descriptions, defaults or examples.",
    bad: `"default": "postgres://app:S3cr3t-Pa55w0rd@db.internal:5432/app"`,
    good: `"description": "Connection string is read from DATABASE_URL on the server; it is not an argument."`,
    references: [REF.cwe(798, "Use of Hard-coded Credentials"), REF.owaspLlm02],
  },
  (ctx, emit) => {
    for (const server of ctx.servers) {
      for (const { location, text } of textFields(server)) {
        for (const hit of findSecrets(text)) {
          emit({
            message: `Credential pattern: ${hit.kind}.`,
            location,
            evidence: hit.redacted,
          });
        }
      }
    }
  },
);
