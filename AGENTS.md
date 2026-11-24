# Barnacle

Barnacle is an independent Rust implementation of a scanner for ClamAV signatures. Use stock clamd as the compatibility reference. The first milestone compares disk-backed and in-memory whole-file hash indexes. See the [experiment plan](docs/plan.md) for the deployment baseline, milestones, and acceptance criteria.

## Communication

- When the user asks to see something, open it in the appropriate local app. Do not only provide a link.
- Write in simple technical English: short sentences (max ~20 words), active voice, one instruction per sentence, no idioms, consistent terms (one name per thing).
- Follow the [Google developer documentation style guide](https://developers.google.com/style) when writing or reviewing documentation, including playbooks and playgrounds.
- Be concise; provide commands/code, not tutorials.
- Ask when ambiguity materially changes scope, behavior, or risk. Otherwise, state a reasonable assumption and proceed.

## Code

- Favor simple, readable code; don't over-engineer or add speculative features.
- Prefer the simplest readable solution; avoid unnecessary abstractions.
- **Surgical edits:** change only lines the request requires. Don't "improve" adjacent code/comments/formatting. Match existing style even if you'd write it differently. Mention unrelated issues/dead code — don't fix unasked. Clean up orphans you created (unused imports/vars); leave pre-existing dead code alone.
- For non-trivial changes, challenge your own work first: "is there a more elegant way?"

## Hard Constraints (never violate)

- **Secrets:** never send secrets (keys, passwords, tokens, connection strings) through the cloud API — reference, never inline. Never read .env, .envrc, *.auto.tfvars, credentials.json, or any likely-secret file; existence is enough. Exclude likely-secret files from searches. Never print environment variables or credential-bearing output.
- **Destructive ops:** never execute destructive operations affecting existing user data or shared state; highlight and hand them to the user. You may remove disposable files and branches you created for the current task. You may also remove code, imports, and variables your changes made unused.
- **Modifying shared/prod state:** always confirm first.
- **Email:** Gmail drafts/sends go ONLY to yavosh@gmail.com, or any address at `nar.cy` / `narity.com` (own infrastructure, for mail-path testing) — never any other recipient.
- **Git:** never push to main. Serialize Git operations that modify repository state. Independent read-only queries may run concurrently.
- **Branches:** choose a suitable named feature branch automatically for requested work. Do not ask permission to create or name it. Stay on an open PR branch for the same concern. Never create a throwaway branch to hold a commit.
- **No AI attribution:** never add AI `Co-Authored-By:` trailers to commits or generated-by footers to PR/MR descriptions.
- `glab` is not installed. Create/update GitLab MRs with `git push` options (`-o merge_request.create -o merge_request.target=main -o merge_request.squash=true -o merge_request.remove_source_branch=true`), not the `glab` CLI.

## Development

- Use Rust 2024. Run these checks from the repository root:

  ```sh
  cargo fmt --check
  cargo test --locked
  ```

- Keep changes focused on the requested milestone. Use safe Rust where practical. Document the safety assumptions for any unsafe memory mapping.
- Use small, harmless fixtures for matcher tests. Keep downloaded databases and generated benchmark indexes outside Git.

## Detection compatibility

- Pin the reference engine version, scan options, and verified database generation for each comparison.
- Compare the reported signature, verdict, and error behavior. Cover exact sizes, wildcard sizes, and competing matches.
- Report a whole-file hash miss as a matcher result. Only a complete scan can produce a clean verdict.
- Report unsupported rules, corrupt indexes, and read failures explicitly. Keep stock clamd authoritative while Barnacle has partial coverage.
- Preserve the full applicable dataset when testing partial loading. Evaluate rule eligibility again for each extracted or normalized object.
- Validate each index generation before activation. Pin one generation for the lifetime of a scan.

## Performance experiments

- Compare implementations using identical signatures, files, and concurrency. Run each implementation separately on the same host.
- Measure cold and warm workloads. Include file-backed pages in cgroup memory measurements. Record throughput and p95 latency alongside memory use.
- Check peak memory during index builds and updates. Use the one-vCPU, 2 GB deployment as the reference.

## Workspace

- Use the sibling depot and infra repositories as references. Confirm before modifying shared or production state.
- Keep secrets out of searches, command output, and commits. Never read credential files or print environment variables.
- Use a named feature branch. Never push to main or run destructive operations on existing user data.
