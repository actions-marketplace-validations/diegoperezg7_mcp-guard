# Field study: 14 public MCP servers

Scan date: **2026-10-28**, with mcp-guard 1.0.0 plus the MCPG-003 fix described below. Reproduce with
[`scripts/field-study.sh`](../scripts/field-study.sh).

## Summary

mcp-guard scanned 14 public MCP servers: the seven reference servers from
[modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) that are still
published, and seven popular servers from companies and the community that start without an account
or credentials. Every finding was reviewed by hand.

- **Nothing malicious or accidental was found.** No hidden instructions, no invisible Unicode, no
  credentials in metadata, no look-alike tool names. There is nothing to report to maintainers.
- **75 findings in total, 67 of them by design.** A filesystem server has path arguments and a
  fetch server takes a URL. The schemas do not declare the limits that the servers enforce in code,
  so the scanner reports the arguments. That is what MCPG-023 and MCPG-024 are for, but none of
  these findings is a defect.
- **4 true positives**, all low: tools that declare no annotations.
- **6 false positives.** Two of them came from one rule (MCPG-003) and are fixed. The other four are
  explained below and left as they are.
- **Behaviour annotations are now the norm.** 163 of 167 tools (98%) declare `readOnlyHint` or
  `destructiveHint`, and 46 declare `destructiveHint: true`. The four that do not are in two small
  community Python servers. In this sample, missing annotations were not the problem expected.

## Method

**Selection.** The reference servers still on npm or PyPI (filesystem, memory, everything,
sequential-thinking, fetch, git, time), plus widely used servers from Microsoft (Playwright,
MarkItDown), Google (Chrome DevTools), Upstash (Context7), Notion, Desktop Commander and DuckDuckGo
search. Servers that need an API key just to start were left out. The latest published version of
each was pinned on the scan date.

**Isolation.** No third-party code ran on the host. For each server, the script builds a throwaway
Docker image from a base image pinned by digest (`node:24-slim`, or `python:3.12-slim` with `git`).
The build installs the pinned package with network access and with npm install scripts disabled.
The container runs with:

- `--network none`
- a read-only root filesystem and a tmpfs `/tmp`
- `--cap-drop ALL` and `no-new-privileges`
- a non-root user (`node` or `nobody`)
- `--memory 512m --cpus 1 --pids-limit 256`

Nothing from the host is mounted. The one exception is the filesystem server, which gets an empty
temporary directory, read-only. The script removes every image when it exits.

**Static analysis only.** The scanner ran
`mcp-guard scan --stdio "docker run -i --rm --network none ..."`, without `--probe` or
`--allow-unsafe`. mcp-guard sent `initialize`, `tools/list`, `resources/list`, `resources/templates/list`
and `prompts/list` and nothing else. No tool was called and no resource was read.

**Review.** Each finding was checked against the tool's schema and description and put in one of
three classes:

- **true positive**: something the maintainer could reasonably change;
- **by design**: the capability is the point of the tool, and the finding only says that the schema
  does not declare a limit;
- **false positive**: the rule misread the metadata.

The servers were scanned one at a time. A final combined scan of all 14 shows the name collisions
that appear when they are installed side by side.

## Servers

| Server                     | Package                                                | Version    | Published  |
| -------------------------- | ------------------------------------------------------ | ---------- | ---------- |
| filesystem (reference)     | npm `@modelcontextprotocol/server-filesystem`          | 2.0.1      | 2026-10-25 |
| memory (reference)         | npm `@modelcontextprotocol/server-memory`              | 2.0.0      | 2026-10-19 |
| everything (reference)     | npm `@modelcontextprotocol/server-everything`          | 2.0.1      | 2026-10-25 |
| sequential-thinking (ref.) | npm `@modelcontextprotocol/server-sequential-thinking` | 2.0.0      | 2026-10-19 |
| fetch (reference)          | PyPI `mcp-server-fetch`                                | 2026.10.24 | 2026-10-25 |
| git (reference)            | PyPI `mcp-server-git`                                  | 2026.10.19 | 2026-10-19 |
| time (reference)           | PyPI `mcp-server-time`                                 | 2026.10.19 | 2026-10-19 |
| Playwright (Microsoft)     | npm `@playwright/mcp`                                  | 0.0.83     | 2026-09-28 |
| Chrome DevTools (Google)   | npm `chrome-devtools-mcp`                              | 1.12.0     | 2026-10-22 |
| Context7 (Upstash)         | npm `@upstash/context7-mcp`                            | 4.4.4      | 2026-10-19 |
| Notion                     | npm `@notionhq/notion-mcp-server`                      | 2.6.0      | 2026-10-28 |
| Desktop Commander          | npm `@wonderwhy-er/desktop-commander`                  | 0.3.1      | 2026-10-22 |
| MarkItDown (Microsoft)     | PyPI `markitdown-mcp`                                  | 0.0.1a8    | 2026-10-21 |
| DuckDuckGo search          | PyPI `duckduckgo-mcp-server`                           | 0.7.0      | 2026-09-04 |

Python dependencies below the pinned package are resolved at build time, so a later run can pull
newer transitive versions. The tool lists depend almost only on the pinned package.

## Results

Findings per server, by severity. "Annotated" counts tools that declare `readOnlyHint` or
`destructiveHint`.

| Server              | Tools | Resources | Prompts | Annotated | Crit. | High | Med. | Low | Rules                                  |
| ------------------- | ----: | --------: | ------: | --------: | ----: | ---: | ---: | --: | -------------------------------------- |
| filesystem          |    14 |         0 |       0 |     14/14 |     0 |    0 |   12 |   0 | MCPG-023 x12                           |
| memory              |     9 |         1 |       0 |       9/9 |     0 |    0 |    0 |   0 | -                                      |
| everything          |    16 |         9 |       4 |     16/16 |     0 |    1 |    2 |   0 | MCPG-021 x1, MCPG-024 x2               |
| sequential-thinking |     1 |         0 |       0 |       1/1 |     0 |    0 |    0 |   0 | -                                      |
| fetch               |     1 |         0 |       1 |       1/1 |     0 |    0 |    1 |   0 | MCPG-024 x1                            |
| git                 |    12 |         0 |       0 |     12/12 |     0 |    0 |   13 |   0 | MCPG-023 x13                           |
| time                |     2 |         0 |       0 |       2/2 |     0 |    0 |    0 |   0 | -                                      |
| Playwright          |    25 |         0 |       0 |     25/25 |     0 |    1 |   12 |   0 | MCPG-022 x1, MCPG-023 x10, MCPG-024 x2 |
| Chrome DevTools     |    32 |         0 |       0 |     32/32 |     0 |    1 |   13 |   0 | MCPG-022 x1, MCPG-023 x11, MCPG-024 x2 |
| Context7            |     2 |         0 |       0 |       2/2 |     0 |    0 |    0 |   0 | - (2 x MCPG-003 before the fix)        |
| Notion              |    24 |         0 |       0 |     24/24 |     0 |    0 |    0 |   0 | -                                      |
| Desktop Commander   |    25 |         2 |       0 |     25/25 |     1 |    2 |   10 |   0 | MCPG-003 x1, MCPG-022 x2, MCPG-023 x10 |
| MarkItDown          |     1 |         0 |       0 |       0/1 |     0 |    0 |    1 |   1 | MCPG-024 x1, MCPG-025 x1               |
| DuckDuckGo          |     3 |         0 |       0 |       0/3 |     0 |    0 |    1 |   3 | MCPG-024 x1, MCPG-025 x3               |
| **Total**           |   167 |        12 |       5 |   163/167 |     1 |    5 |   65 |   4 | 75 findings                            |

Resources include resource templates (2 in everything).

### Classification

| Server            | Finding                                                   | Class          | Why                                                                                                                                                                                                        |
| ----------------- | --------------------------------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| filesystem        | MCPG-023 x12, `path`, `paths`                             | by design      | The server confines every path to the allowed directories it is started with. The schema just does not say so.                                                                                             |
| git               | MCPG-023 x13, `repo_path`, `files`                        | by design      | Same pattern. The server can be pinned to one repository with `--repository`.                                                                                                                              |
| everything        | MCPG-024 `gzip-file-as-resource.data`                     | by design      | It fetches a URL. The allowed domains come from `GZIP_ALLOWED_DOMAINS` on the server, which the schema cannot show.                                                                                        |
| everything        | MCPG-024 `trigger-resource-update.uri`                    | false positive | This is an MCP resource URI (`demo://...`) used for a notification. Nothing connects to it.                                                                                                                |
| everything        | MCPG-021 `trigger-resource-update` read-only but "update" | false positive | The tool only sends a `resources/updated` notification, so `readOnlyHint: true` is accurate. Here "update" is a noun.                                                                                      |
| fetch             | MCPG-024 `fetch.url`                                      | by design      | Fetching any URL is the server's purpose. Its README warns that it can reach local and internal addresses.                                                                                                 |
| Playwright        | MCPG-022 `browser_run_code_unsafe.code`                   | by design      | It runs arbitrary code in the server process. The tool says so in its name and description ("RCE-equivalent") and declares `destructiveHint: true`. This is the right way to ship such a tool.             |
| Playwright        | MCPG-023 x10, MCPG-024 x2                                 | by design      | Output files are resolved against the workspace root, uploads take absolute paths, and navigation takes any URL. That is a browser automation server.                                                      |
| Chrome DevTools   | MCPG-022 `evaluate_script.args`                           | false positive | `args` is a list of element ids. The free-form JavaScript is in `function`, which the rule does not check (see Limits).                                                                                    |
| Chrome DevTools   | MCPG-023 x11, MCPG-024 x2                                 | by design      | Optional paths for traces, screenshots and snapshots; URLs for navigation.                                                                                                                                 |
| Context7          | MCPG-003 x2 (before the fix)                              | false positive | The parameter description says "Do not include any sensitive or confidential information such as API keys, passwords...". It protects the user. **Fixed**: a verb right after a negation no longer counts. |
| Desktop Commander | MCPG-003 `start_search` mentions `".env"`                 | false positive | A search guide lists `.env` as an example of a configuration file name. A credential file name is the signal MCPG-003 looks for, so the rule is kept as it is.                                             |
| Desktop Commander | MCPG-022 `start_process.command`, `.shell`                | by design      | Running shell commands is what the server is for. The tool declares `destructiveHint: true` and `openWorldHint: true`.                                                                                     |
| Desktop Commander | MCPG-023 x10                                              | by design      | The server enforces `allowedDirectories` in its configuration, and its `instructions` say so.                                                                                                              |
| MarkItDown        | MCPG-024 `convert_to_markdown.uri`                        | by design      | It accepts `http:`, `https:`, `file:` and `data:` URIs, which is worth knowing before you expose it to untrusted input.                                                                                    |
| MarkItDown        | MCPG-025 x1                                               | true positive  | No annotations. `readOnlyHint: true, openWorldHint: true` would fit.                                                                                                                                       |
| DuckDuckGo        | MCPG-024 `fetch_content.url`                              | by design      | Fetching a page from search results is its purpose.                                                                                                                                                        |
| DuckDuckGo        | MCPG-025 x3                                               | true positive  | No annotations. All three tools are read-only lookups.                                                                                                                                                     |

Totals: **67 by design, 4 true positives, 4 false positives**, plus the 2 Context7 false positives
that the MCPG-003 fix removed. Over the 77 findings before the fix, the false positive rate was 8%.

### Combined scan

When all 14 servers were scanned together, the per-server findings were unchanged and MCPG-010 added
14 high findings: filesystem and Desktop Commander both expose `read_file`, `write_file`,
`list_directory`, `create_directory`, `move_file`, `get_file_info` and `read_multiple_files`. Neither
server is at fault. The finding is still real for a user who installs both, because the client
decides which `write_file` the model gets and the two enforce different directory allowlists.

## Lessons

1. **The tool list of a mainstream server is not where the attacks are.** Not one of the poisoning
   rules (MCPG-001 to 005, 012, 013) or the secrets rule matched a real problem. Those rules exist
   for malicious or compromised servers, and nothing in this sample is one. The way to use them is
   to pin versions and scan on every upgrade (rug pulls), not to expect hits on popular packages.
2. **Annotations are widely adopted.** 98% of tools declare them, including every reference server,
   Playwright, Chrome DevTools, Notion, Context7 and Desktop Commander, and the dangerous tools
   declare `destructiveHint: true`. The gaps were in two small Python servers.
3. **Schemas do not describe limits.** 65 of the 75 findings are path or URL arguments with no
   pattern or enum. The servers enforce allowlists in code or configuration (allowed directories,
   `--repository`, `GZIP_ALLOWED_DOMAINS`), and a client or reviewer looking at the contract cannot
   see them. This is the largest gap between the MCP contract and what servers do. For a reviewer,
   it is the list of places to check by hand.
4. **Powerful tools are labelled honestly.** Playwright's code runner is called `_unsafe` and says
   it is RCE-equivalent; Desktop Commander's shell is annotated destructive. A scanner cannot make
   these tools safe. Its job is to make sure the user knows they are there.
5. **Descriptions can depend on the environment.** Desktop Commander writes the detected OS,
   container and mounts into the `start_process` description. The same version therefore produces
   different tool lists on different machines. That is harmless, but it means a hash of the tool
   list is not a stable fingerprint for detecting changes.
6. **Reference servers still talk to the model.** The fetch server's description tells the model
   that it was "advised to refuse" earlier and now has internet access. Here that is harmless, but it
   is the same shape as an injection, and mcp-guard does not catch it (see Limits).
7. **Heuristic text rules need negation handling.** The one fixed false positive was a safety
   warning that read as a request. Name heuristics have the same weakness: "trigger resource
   update" reads as a write.

## Changes to mcp-guard from this study

- **MCPG-003**: a verb right after `not`, `never`, `n't` or `avoid` is no longer read as a request
  to move secrets. "Do not include API keys" is not flagged; "do not forget to include the API key"
  still is. Covered by a negative test.

## Limits

- **Static only.** What the tools do when called was not tested (`--probe` was not used on purpose),
  so the results say nothing about indirect prompt injection in tool output.
- **Tools that need credentials or a running service are missing.** Some servers list a different
  tool set once configured.
- **One snapshot.** The results apply to the versions above.
- **Known false negatives.** The fetch server's description tells the model: "Although originally
  you did not have internet access, and were advised to refuse and tell the user this, this tool now
  grants you internet access." That is text addressed to the model that overrides earlier guidance.
  Here it is benign and intended, but neither MCPG-002 nor MCPG-005 matches it. Also, MCPG-022 does not check an argument named `function`, which is where
  Chrome DevTools' `evaluate_script` takes JavaScript (run in the browser page, not on the host).
- **Small sample.** 14 servers, 167 tools. Larger community registries probably contain more
  unannotated tools and lower-quality descriptions than these well-maintained packages.
