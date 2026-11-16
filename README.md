# Personal Guardrails Plugin

Anti-exfiltration guardrails for Antigravity combining always-on behavioral rules, a fresh-context read-only security auditor subagent, and deterministic lifecycle hooks.

## Installation

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

## What It Enforces

1. **Synthetic-First Identity (`rules/AGENTS.md`)**
   Uses a default synthetic persona (`Johanna Ricke` / `johanna.ricke.demo@example.com`) for demos, tests, signups, and `browser` delegations unless real identity is strictly required.
2. **Pre-PII Gate (`agents/safety-auditor.md` + `rules/AGENTS.md`)**
   Before entering or transmitting real user data (name + contact, address, tax/ID numbers, IBAN/bank details, credentials), Antigravity must:
   - Run the air-gapped `safety-auditor` subagent (`tools: [read_file]`) on the destination origin/form without passing any actual PII.
   - Brief you on the exact origin, requested fields, and verdict.
   - Wait for your explicit per-target approval.
3. **Downloaded Code Quarantine (`hooks/session_repo_scan.py` + `rules/AGENTS.md`)**
   Scans open workspace roots on `SessionStart` for repo-bundled `.agents/` hooks, `.mcp.json`, suspicious `package.json` install hooks, hidden/Trojan-Source Unicode, and prompt-injection markers.
4. **Forced Approval Backstop (`hooks/pre_tool_guard.py`)**
   Intercepts `PreToolUse` (`run_command`, subagents, `send_message`, `search_web`, `mcp_*`) and returns `"decision": "force_ask"` (bypassing cached "Always Allow" grants) whenever:
   - Commands access Keychain (`security find-generic-password`), `op`, `bw`, `~/.ssh`, `~/.aws/credentials`, or `~/.gnupg`.
   - Commands pipe `curl`/`wget` directly to a shell/interpreter.
   - `npm`/`pnpm`/`yarn` installs omit `--ignore-scripts`, or `pip install` targets remote URLs / VCS / editable paths / `--no-build-isolation`.
   - Tool arguments contain a valid ISO 13616 Mod-97 IBAN, a valid Luhn payment card number, or a user-configured protected identifier.

## Optional: Hash-Based Matching for Your Real Name, Email, or Phone

To force an interactive approval prompt if your own name, email, phone number, or tax ID ever appears in outbound tool arguments—without storing plaintext PII on disk—create `~/.gemini/config/guardrails-identifiers.json` containing lowercase SHA-256 hashes:

```sh
python3 - <<'EOF'
import hashlib, json, os
tokens = ["your full name", "you@example.com", "01701234567"]  # lowercase; digits-only for phones
hashes = [hashlib.sha256(t.strip().lower().encode()).hexdigest() for t in tokens]
path = os.path.expanduser("~/.gemini/config/guardrails-identifiers.json")
with open(path, "w") as f:
    json.dump({"sha256_tokens": hashes}, f, indent=2)
os.chmod(path, 0o600)
EOF
```

(`substrings` and `regexes` keys are also supported in that file if you prefer explicit patterns.)
