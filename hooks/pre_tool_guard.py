#!/usr/bin/env python3
"""PreToolUse hook enforcing forced confirmation on secrets, sensitive IDs, and risky installs."""

import hashlib
import json
import os
import re
import sys
from urllib.parse import unquote, unquote_plus, urlparse

# Official ISO 13616 IBAN lengths by two-letter country code.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22,
    "VG": 24, "XK": 20,
}

# Canonical ISO/documentation/Stripe test IBANs that should not cause alert fatigue.
TEST_IBANS = {
    "DE89370400440532013000",
    "GB29NWBK60161331926819",
    "GB82WEST12345698765432",
    "CH9300762011623852957",
    "FR1420041010050500013M02606",
    "NL91ABNA0417164300",
    "AT611904300234573201",
}

# Standard payment-processor test cards (Stripe / Adyen / Braintree docs).
TEST_CARDS = {
    "4242424242424242",
    "4111111111111111",
    "4000056655665556",
    "4000000000000002",
    "5555555555554444",
    "5105105105105100",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
}

INVISIBLE_CHARS_RE = re.compile(
    r"[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\uFE00-\uFE0F]"
)
IBAN_START_RE = re.compile(r"(?<![A-Za-z0-9])(?=([A-Za-z]{2}[0-9]{2}))")
IBAN_SEPARATORS = set(" -_.")
CARD_RUN_RE = re.compile(r"(?<![0-9])[0-9](?:[ \-._]?[0-9]){12,24}(?![0-9])")

# Tool routing categories (matched via ".*" in hooks.json and filtered here).
FILE_ACCESS_TOOLS = {
    "read_file",
    "view_file",
    "view_file_outline",
    "view_code_item",
    "write_file",
    "edit_file",
    "grep_search",
    "find_by_name",
    "read_resource",
}

OUTBOUND_AND_AGENT_TOOLS = {
    "run_command",
    "send_message",
    "search_web",
    "call_mcp_tool",
    "swarm",
    "run_workflow",
}

SAFE_ENV_BASENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
    ".env.schema",
    ".env.types",
}

SENSITIVE_BASENAMES = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "guardrails-identifiers.json",
    "protected_identifiers.json",
}

SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"(?:^|/)\.ssh(?:/|$)", re.IGNORECASE), "SSH directory/key access"),
    (re.compile(r"(?:^|/)\.aws/(?:credentials|config)$", re.IGNORECASE), "AWS credentials/config access"),
    (re.compile(r"(?:^|/)\.gnupg(?:/|$)", re.IGNORECASE), "GnuPG keyring access"),
    (re.compile(r"(?:^|/)Library/Keychains(?:/|$)", re.IGNORECASE), "macOS Keychain path access"),
    (re.compile(r"(?:^|/)\.kube/config$", re.IGNORECASE), "Kubernetes kubeconfig access"),
    (re.compile(r"(?:^|/)\.docker/config\.json$", re.IGNORECASE), "Docker registry auth config access"),
    (re.compile(r"(?:^|/)\.config/gh/hosts\.yml$", re.IGNORECASE), "GitHub CLI auth token file access"),
    (re.compile(r"(?:^|/)\.config/gcloud/(?:credentials|access_tokens|application_default_credentials)", re.IGNORECASE), "gcloud credentials access"),
    (re.compile(r"(?:^|/)\.gemini/[^/]+/(?:plugins/[^/]+/)?auth\.json$", re.IGNORECASE), "Plugin OAuth token file access"),
    (re.compile(r"(?:^|/)\.gemini/config/plugins/[^/]+/.*auth.*\.json$", re.IGNORECASE), "Plugin auth file access"),
]

SENSITIVE_KEY_EXTS = (".pem", ".p12", ".pfx", ".kdbx")

# Shell CLI patterns checked at command-invocation position (segment start, command substitution, or eval/-c).
SECRET_CLI_PATTERNS = [
    (
        re.compile(
            r"^(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?security\s+"
            r"(?:find-generic-password|find-internet-password|dump-keychain|export)\b"
        ),
        "macOS Keychain secret access detected",
    ),
    (
        re.compile(
            r"^(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?op\s+"
            r"(?:read|item|inject|run|signin)\b"
        ),
        "1Password CLI (`op`) secret access detected",
    ),
    (
        re.compile(
            r"^(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?bw\s+"
            r"(?:get|unlock|export)\b"
        ),
        "Bitwarden CLI (`bw`) secret access detected",
    ),
    (
        re.compile(r"^(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?gh\s+auth\s+token\b"),
        "GitHub CLI token lookup (`gh auth token`) detected",
    ),
    (
        re.compile(
            r"^(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?gcloud\s+auth\s+"
            r"print-(?:access|identity)-token\b"
        ),
        "gcloud token lookup detected",
    ),
]

# Shell path patterns checked anywhere in a command line.
SECRET_CMD_PATTERNS = [
    (
        re.compile(r"Library/Keychains"),
        "macOS Keychain path access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.ssh(?:/|\b)"),
        "SSH directory/key access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.aws/(?:credentials|config)\b"),
        "AWS credentials/config file access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.gnupg(?:/|\b)"),
        "GnuPG keyring directory access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.(?:netrc|npmrc|pypirc)\b"),
        "Credential rc file (`.netrc`/`.npmrc`/`.pypirc`) access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.kube/config\b"),
        "Kubernetes kubeconfig access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.docker/config\.json\b"),
        "Docker auth config access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.config/gh/hosts\.yml\b"),
        "GitHub CLI hosts token file access detected",
    ),
    (
        re.compile(r"(?:^|[\s/~\"'=])\.config/gcloud/(?:credentials|access_tokens|application_default_credentials)"),
        "gcloud credentials access detected",
    ),
    (
        re.compile(r"\.gemini/[^\s\"']*auth\.json\b"),
        "Plugin OAuth token (`auth.json`) access detected",
    ),
]

CMD_SUBST_RE = re.compile(r"\$\(([^)]+)\)|`([^`]+)`")
SHELL_EVAL_RE = re.compile(r"^(?:(?:sudo|env)\s+(?:-\S+\s+)*)*(?:/[\w/.-]*/)?(?:(?:ba|z|da|k)?sh\s+-c|eval)\s+(.+)$")

PIPE_EXEC_RE = re.compile(
    r"(?:"
    r"\b(?:curl|wget)\b[^;\n]*\|\s*(?:(?:sudo|env)\s+(?:-[A-Za-z0-9=_-]+\s+)*)*(?:/[\w/.-]*/)?(?:(?:ba|z|da|k)?sh|python3?|perl|ruby|node)\b"
    r"|\b(?:(?:ba|z|da|k)?sh|source|\.)\s+<\(\s*(?:curl|wget)\b"
    r"|\b(?:(?:ba|z|da|k)?sh|eval)\b[^;\n]*\$\(\s*(?:curl|wget)\b"
    r")"
)

JS_INSTALL_RE = re.compile(
    r"(?:^|\s)(?:npm|pnpm|bun)(?:\s+(?:--[a-z0-9-]+(?:\s+\S+)?|-[a-zA-Z](?:\s+\S+)?))*\s+(?:install|i|ci|add)\b"
)
YARN_INSTALL_RE = re.compile(
    r"(?:^|\s)yarn(?:\s*$|\s+(?:install|add|--frozen-lockfile)\b)"
)
NPX_EXEC_RE = re.compile(r"(?:^|\s)npx\b")
IGNORE_SCRIPTS_VALID_RE = re.compile(r"(?:^|\s)--ignore-scripts(?:\s|$|=(?:true|1)(?:\s|$))", re.IGNORECASE)
PIP_INSTALL_RE = re.compile(r"(?:^|\s)(?:uv\s+)?pip3?\s+install\b")
PIP_RISKY_FLAG_RE = re.compile(
    r"(?:git\+|https?://|--no-build-isolation|(?:^|\s)(?:-e|--editable)(?:\s|=))"
)


def force_ask(reason):
    """Return a forced-approval PreToolUse decision."""
    return {"decision": "force_ask", "reason": f"[Personal Guardrails] {reason}"}


def strip_invisible(text):
    """Strip zero-width, Bidi, and invisible formatting characters."""
    return INVISIBLE_CHARS_RE.sub("", text)


def split_shell_segments(command_line):
    """Split a shell command on control operators outside quotes and strip unquoted `#` comments."""
    segments = []
    cur = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(command_line)

    while i < n:
        ch = command_line[i]
        if escaped:
            cur.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\" and not in_single:
            cur.append(ch)
            escaped = True
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            cur.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            cur.append(ch)
            i += 1
            continue

        if not in_single and not in_double:
            if ch == "#" and (not cur or cur[-1].isspace()):
                # Skip shell comment to end of line
                while i < n and command_line[i] != "\n":
                    i += 1
                continue
            if ch in ";\n":
                seg = "".join(cur).strip()
                if seg:
                    segments.append(seg)
                cur = []
                i += 1
                continue
            if ch in "&|":
                if i + 1 < n and command_line[i + 1] == ch:
                    i += 2
                else:
                    i += 1
                seg = "".join(cur).strip()
                if seg:
                    segments.append(seg)
                cur = []
                continue

        cur.append(ch)
        i += 1

    seg = "".join(cur).strip()
    if seg:
        segments.append(seg)
    return segments


def extract_executable_segments(command_line):
    """Collect top-level shell segments plus nested `$(...)`, backtick, and `sh -c`/`eval` bodies."""
    top_segments = split_shell_segments(command_line)
    all_segments = list(top_segments)
    for m in CMD_SUBST_RE.finditer(command_line):
        inner = m.group(1) or m.group(2) or ""
        all_segments.extend(split_shell_segments(inner))
    for seg in top_segments:
        eval_m = SHELL_EVAL_RE.match(seg)
        if eval_m:
            body = eval_m.group(1).strip().strip("'\"")
            all_segments.extend(split_shell_segments(body))
    return top_segments, all_segments


def check_run_command(command_line, bypass_sandbox=False):
    """Inspect shell command lines for secret reads, piped downloads, and install scripts."""
    cleaned = strip_invisible(command_line)
    for pat, message in SECRET_CMD_PATTERNS:
        if pat.search(cleaned):
            return force_ask(f"{message}. Explicit confirmation required.")

    if PIPE_EXEC_RE.search(cleaned):
        return force_ask("Remote download piped directly to an interpreter. Explicit confirmation required.")

    top_segments, all_segments = extract_executable_segments(cleaned)
    for seg in all_segments:
        for pat, message in SECRET_CLI_PATTERNS:
            if pat.search(seg):
                return force_ask(f"{message}. Explicit confirmation required.")

    for seg in all_segments:
        if (JS_INSTALL_RE.search(seg) or YARN_INSTALL_RE.search(seg)) and not IGNORE_SCRIPTS_VALID_RE.search(seg):
            return force_ask(
                "Package install runs lifecycle scripts (missing valid `--ignore-scripts`). Confirm before executing."
            )
        if bypass_sandbox and NPX_EXEC_RE.search(seg) and not re.search(r"--no-install\b", seg):
            return force_ask(
                "Unsandboxed `npx` can download and execute remote packages. Confirm before executing."
            )
        if PIP_INSTALL_RE.search(seg) and PIP_RISKY_FLAG_RE.search(seg):
            return force_ask(
                "pip install references a remote URL, VCS repo, editable path, or disabled build isolation. Confirm before executing."
            )

    return None


def normalize_candidate_path(raw_path):
    """Normalize a file path or file:// URI into a clean POSIX path string."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return ""
    val = raw_path.strip()
    if val.startswith("file://"):
        val = unquote(urlparse(val).path)
    val = os.path.expanduser(val)
    val = val.replace("\\", "/")
    return os.path.normpath(val).replace("\\", "/")


def check_sensitive_file_path(args):
    """Gate file-access tools only when targeting sensitive credential/key/dotenv paths."""
    if not isinstance(args, dict):
        return None

    candidate_keys = ("Path", "path", "SearchPath", "searchPath", "Directory", "directory", "Uri", "uri")
    paths = []
    for key in candidate_keys:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            paths.append(val)

    for raw in paths:
        norm = normalize_candidate_path(raw)
        if not norm:
            continue
        base = os.path.basename(norm)
        base_lower = base.lower()

        if base_lower == ".env" or (
            base_lower.startswith(".env.") and base_lower not in SAFE_ENV_BASENAMES
        ):
            return force_ask(f"Sensitive environment file (`{base}`) access detected. Confirm before proceeding.")

        if base_lower in SENSITIVE_BASENAMES:
            return force_ask(f"Sensitive credential file (`{base}`) access detected. Confirm before proceeding.")

        if any(base_lower.endswith(ext) for ext in SENSITIVE_KEY_EXTS):
            if not any(tok in base_lower for tok in ("test", "fixture", "mock", "sample", "example", "public")):
                return force_ask(f"Private key/keystore file (`{base}`) access detected. Confirm before proceeding.")

        for pat, label in SENSITIVE_PATH_PATTERNS:
            if pat.search(norm):
                return force_ask(f"{label} (`{base}`). Confirm before proceeding.")

    return None


def verify_iban_mod97(compact):
    """Verify country code, official length, alphanumeric payload, and ISO 13616 Mod-97."""
    country = compact[:2]
    expected_len = IBAN_LENGTHS.get(country)
    if expected_len is None or len(compact) != expected_len:
        return False
    if compact in TEST_IBANS:
        return False
    if not compact[2:4].isdigit() or not compact[4:].isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric_str = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    return int(numeric_str) % 97 == 1


def contains_valid_iban(text):
    """Scan every valid country-code start position and slice to exact country IBAN length."""
    n = len(text)
    for match in IBAN_START_RE.finditer(text):
        country = match.group(1)[:2].upper()
        expected_len = IBAN_LENGTHS.get(country)
        if expected_len is None:
            continue

        chars = []
        pos = match.start()
        while pos < n and len(chars) < expected_len:
            ch = text[pos]
            if ch.isalnum():
                chars.append(ch.upper())
            elif ch in IBAN_SEPARATORS:
                pass
            else:
                break
            pos += 1

        if len(chars) != expected_len:
            continue

        # Ensure the candidate ends on a token boundary (not mid-hash/word).
        if pos < n and text[pos].isalnum():
            continue

        if verify_iban_mod97("".join(chars)):
            return True
    return False


def matches_card_iin(digits):
    """Verify candidate matches real major payment-card network IIN prefix and valid length."""
    length = len(digits)
    if digits.startswith("4") and length in (13, 16, 19):
        return True
    if length == 16:
        p2 = int(digits[:2])
        p4 = int(digits[:4])
        if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
            return True
    if length == 15 and digits[:2] in ("34", "37"):
        return True
    if length in (16, 19):
        if digits.startswith("6011") or digits.startswith("65") or 644 <= int(digits[:3]) <= 649:
            return True
    if 14 <= length <= 19:
        p3 = int(digits[:3])
        p4 = int(digits[:4])
        if 300 <= p3 <= 305 or digits[:2] in ("36", "38", "39", "62") or 3528 <= p4 <= 3589:
            return True
    return False


def passes_luhn(digits):
    """Standard Luhn mod-10 checksum check."""
    total = 0
    for idx, ch in enumerate(digits[::-1]):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def contains_valid_luhn_card(text):
    """Check card digit runs using group-boundary slices and sliding windows for major IIN networks."""
    for match in CARD_RUN_RE.finditer(text):
        raw = match.group(0)
        groups = re.findall(r"[0-9]+", raw)
        candidates = set()

        # Check all contiguous digit-group combinations (handles "4000 0566 5566 5556 12/27" & CVV).
        for start_idx in range(len(groups)):
            acc = ""
            for end_idx in range(start_idx, len(groups)):
                acc += groups[end_idx]
                if 13 <= len(acc) <= 19:
                    candidates.add(acc)
                elif len(acc) > 19:
                    break

        # Also check full contiguous digit strings (handles unspaced cards + trailing digits).
        all_digits = "".join(groups)
        if 13 <= len(all_digits) <= 19:
            candidates.add(all_digits)
        elif len(all_digits) > 19:
            for win_len in (16, 15, 19, 14, 13):
                for start in range(0, len(all_digits) - win_len + 1):
                    candidates.add(all_digits[start:start + win_len])

        for digits in candidates:
            if digits in TEST_CARDS:
                continue
            if matches_card_iin(digits) and passes_luhn(digits):
                return True
    return False


def collect_strings(node, out):
    """Recursively collect all string values from toolCall.args."""
    if isinstance(node, str):
        if node:
            out.append(node)
    elif isinstance(node, dict):
        for val in node.values():
            collect_strings(val, out)
    elif isinstance(node, list):
        for item in node:
            collect_strings(item, out)


def load_protected_identifiers():
    """Load optional user-configured substrings, regexes, and unsalted sha256_tokens."""
    paths = []
    plugin_data = os.environ.get("PLUGIN_DATA")
    if plugin_data:
        paths.append(os.path.join(plugin_data, "protected_identifiers.json"))
    paths.append(os.path.expanduser("~/.gemini/config/guardrails-identifiers.json"))

    substrings = []
    regexes = []
    sha256_tokens = set()

    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue

        for item in data.get("substrings") or []:
            if isinstance(item, str) and item.strip():
                substrings.append(item.strip().lower())
        for pattern in data.get("regexes") or []:
            if isinstance(pattern, str) and pattern:
                try:
                    regexes.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    pass
        for digest in data.get("sha256_tokens") or []:
            if isinstance(digest, str) and len(digest.strip()) == 64:
                sha256_tokens.add(digest.strip().lower())

    return substrings, regexes, sha256_tokens


def sha256_hex(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def check_protected_identifiers(text, substrings, regexes, sha256_tokens):
    """Check a string against optional substrings, regexes, and unsalted sha256 tokens."""
    if not (substrings or regexes or sha256_tokens):
        return False

    lower_text = text.lower()
    for sub in substrings:
        if sub in lower_text:
            return True

    for pat in regexes:
        if pat.search(text):
            return True

    if sha256_tokens:
        candidates = set()
        for email in re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", lower_text):
            candidates.add(email)

        # Unicode-aware words (supports umlauts/accents) and 1-, 2-, and 3-word phrases.
        words = re.findall(r"[^\W_]+", lower_text, flags=re.UNICODE)
        candidates.update(words)
        for i in range(len(words) - 1):
            candidates.add(f"{words[i]} {words[i + 1]}")
        for i in range(len(words) - 2):
            candidates.add(f"{words[i]} {words[i + 1]} {words[i + 2]}")

        for token in re.findall(r"[^\s,;:\"'(){}\[\]<>]+", lower_text):
            candidates.add(token)

        for num_cand in re.findall(r"\+?[0-9][0-9 .\-/()]{4,}[0-9]", text):
            digits = re.sub(r"[^0-9]", "", num_cand)
            if len(digits) >= 6:
                candidates.add(digits)
                candidates.add(f"+{digits}")
                # Common European/US country-code -> leading-0 local phone normalization.
                if digits.startswith(("49", "41", "43", "44", "33")) and len(digits) >= 10:
                    candidates.add("0" + digits[2:])
        for digits in re.findall(r"[0-9]{6,}", text):
            candidates.add(digits)

        for cand in candidates:
            if sha256_hex(cand) in sha256_tokens:
                return True

    return False


def text_variants(raw_text):
    """Return raw cleaned text plus URL-decoded variant(s) to catch percent-encoded egress."""
    cleaned = strip_invisible(raw_text)
    variants = [cleaned]
    if "%" in cleaned or "+" in cleaned:
        once = strip_invisible(unquote_plus(cleaned))
        if once != cleaned:
            variants.append(once)
            if "%" in once:
                twice = strip_invisible(unquote_plus(once))
                if twice != once:
                    variants.append(twice)
    return variants


def check_sensitive_strings(args):
    """Scan all string arguments for IBANs, payment cards, or protected identifiers."""
    strings = []
    collect_strings(args, strings)
    if not strings:
        return None

    substrings, regexes, sha256_tokens = load_protected_identifiers()

    for raw_text in strings:
        for text in text_variants(raw_text):
            if contains_valid_iban(text):
                return force_ask(
                    "Valid IBAN detected in tool arguments. Confirm origin audit and user approval before proceeding."
                )

            if contains_valid_luhn_card(text):
                return force_ask(
                    "Valid payment card number detected in tool arguments. Confirm origin audit and user approval before proceeding."
                )

            if check_protected_identifiers(text, substrings, regexes, sha256_tokens):
                return force_ask(
                    "Protected personal identifier detected in tool arguments. Confirm origin audit and user approval before proceeding."
                )

    return None


def should_scan_arguments(tool_name):
    """Return True if a tool can carry data outbound or across agent boundaries."""
    if tool_name in OUTBOUND_AND_AGENT_TOOLS:
        return True
    if "subagent" in tool_name:
        return True
    if tool_name.startswith(("mcp_", "browser_", "fetch", "read_url", "http")):
        return True
    return False


def main():
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    tool_call = payload.get("toolCall") or {}
    tool_name = str(tool_call.get("name") or "").lower()
    args = tool_call.get("args")

    if tool_name in FILE_ACCESS_TOOLS:
        path_verdict = check_sensitive_file_path(args)
        if path_verdict is not None:
            print(json.dumps(path_verdict))
            return
        # Fast-path normal workspace file reads/edits without running PII regexes on paths/code.
        return

    if tool_name == "run_command" and isinstance(args, dict):
        cmd = str(args.get("CommandLine") or "")
        bypass = bool(args.get("BypassSandbox"))
        verdict = check_run_command(cmd, bypass_sandbox=bypass)
        if verdict is not None:
            print(json.dumps(verdict))
            return

    if should_scan_arguments(tool_name):
        sensitive_verdict = check_sensitive_strings(args)
        if sensitive_verdict is not None:
            print(json.dumps(sensitive_verdict))
            return

    # Neutral passthrough: empty stdout with exit 0 delegates to Antigravity's built-in policy.
    return


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            json.dumps(
                force_ask(f"Hook check error ({type(exc).__name__}); explicit confirmation required.")
            )
        )
