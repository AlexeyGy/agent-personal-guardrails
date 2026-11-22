# Personal Guardrails Plugin for Antigravity (`agy`)

Local coding and browser agents ship with Simon Willison's [**"lethal trifecta"**](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) enabled out of the box: access to **private data**, exposure to **untrusted content** (repos, issues, web pages), and **external communication** tools. Prompt instructions in `AGENTS.md` sit in the same context plane as untrusted text and cannot serve as a security boundary on their own.

Antigravity's OS terminal sandbox, browser domain allowlist, and approval prompts provide the **hard walls**. This plugin adds **safer defaults, isolated triage, and deterministic Python tripwires** on top so you can keep local agents useful without turning cached `"Always Allow"` grants into silent exfiltration paths.

## Defense Layers vs. The Lethal Trifecta

| Trifecta Leg | Hard Harness Barrier (Built-In) | What This Plugin Adds |
| :--- | :--- | :--- |
| **1. Private Data** | OS filesystem sandbox + non-workspace file prompts | **Synthetic-first persona** (`rules/AGENTS.md`) keeps real PII out of routine browser/demo flows. **`PreToolUse` hook** (`hooks/pre_tool_guard.py`) forces `force_ask` when `read_file`, `write_file`/`edit_file`, or `run_command` targets Keychain, `op`/`bw`/`gh`/`gcloud`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`/`.npmrc`/`.pypirc`, `~/.kube/config`, `~/.gemini/**/auth.json`, or `.env` files. |
| **2. Untrusted Content** | Read-only subagent isolation + sandboxed installs | **`SessionStart` & post-`git clone` scanner** (`hooks/session_repo_scan.py`) flags repo-bundled `.agents/` hooks, `.mcp.json`, risky `package.json` lifecycle scripts, invisible/Bidi/Variation-Selector Unicode, and prompt-injection markers (with sanitized filenames). **`safety-auditor`** (`agents/safety-auditor.md`) triages unfamiliar repos and target origins in a fresh, read-only, network-less context. |
| **3. External Egress** | No-network terminal sandbox + browser domain allowlist + approval clicks | **Deterministic `PreToolUse` egress tripwire** (`hooks/pre_tool_guard.py`) inspects outbound/agent/MCP tool arguments (raw and URL-decoded, stripping invisible chars) and triggers `force_ask` on valid ISO 13616 Mod-97 IBANs, Luhn-valid payment cards (major IIN prefixes including Mastercard 2-series), user-configured SHA-256 identifiers, `curl \| sh` pipes, and `npm`/`pnpm`/`yarn`/`bun` installs missing `--ignore-scripts`. |

## Installation

*(Hook commands require `python3` in `PATH` on macOS/Linux.)*

### Antigravity CLI

```sh
agy plugin install https://github.com/AlexeyGy/agent-personal-guardrails
```

### Antigravity Desktop App (Git Clone)

```sh
git clone https://github.com/AlexeyGy/agent-personal-guardrails.git ~/.gemini/config/plugins/personal-guardrails
```

To update a cloned install later:

```sh
git -C ~/.gemini/config/plugins/personal-guardrails pull
```

## Optional: Hash-Based Matching for Your Real Name, Email, or Phone

To trigger `force_ask` if your own name, email, phone number, or tax ID appears in outbound tool arguments without storing plaintext strings in dotfiles, create `~/.gemini/config/guardrails-identifiers.json` containing lowercase SHA-256 hashes:

```sh
python3 - <<'EOF'
import hashlib, json, os
# Use full names, emails, or full phone numbers — avoid short single words
# like your first name or OS username (which appear in home-directory paths).
tokens = ["your full name", "you@example.com", "01701234567", "+491701234567"]
hashes = [hashlib.sha256(t.strip().lower().encode()).hexdigest() for t in tokens]
path = os.path.expanduser("~/.gemini/config/guardrails-identifiers.json")
with open(path, "w") as f:
    json.dump({"sha256_tokens": hashes}, f, indent=2)
os.chmod(path, 0o600)
EOF
```

(`substrings` and `regexes` keys are also supported in that file if you prefer explicit patterns. Standard ISO/Stripe test IBANs and test cards are allowlisted to avoid dev/test alert fatigue.)

## Honest Limitations & Non-Goals

- **Tripwire, not an unbreakable DLP wall:** Argument scanning catches plaintext and URL-encoded leaks, not arbitrary custom obfuscation (e.g., bespoke encoding) or sensitive data passed by opaque file reference. Keep Antigravity's OS sandbox and browser allowlist enabled.
- **Unsalted SHA-256 hashes:** Hashing avoids leaving plaintext PII in config files or accidental backups, but unsalted hashes of low-entropy domains (like phone numbers) can still be brute-forced offline if an attacker already controls your disk.
- **Network-less, not hardware air-gapped:** `safety-auditor` has no network tools (`tools: [read_file]`), but its Markdown verdict still returns to the main coordinator. Never pass actual secrets to the auditor; pass only URLs and field categories.
- **Startup and clone scans warn; they do not block workspace loading:** Opening an untrusted repository directly as a top-level workspace still allows Antigravity to discover its `.agents/` directory. Clone unfamiliar code into a quarantine subdirectory first.
- **Platform:** Hook shell wrappers in `hooks.json` target macOS and Linux (`sh -c`).
