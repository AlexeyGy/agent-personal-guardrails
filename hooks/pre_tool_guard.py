#!/usr/bin/env python3
"""PreToolUse hook enforcing forced confirmation on secrets, sensitive IDs, and risky installs."""

import hashlib
import json
import os
import re
import sys

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

IBAN_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}(?:[ -]?[A-Za-z0-9]){10,30}(?![A-Za-z0-9])"
)
CARD_CANDIDATE_RE = re.compile(r"(?<![0-9])[3-6](?:[ -]?[0-9]){12,18}(?![0-9])")

TEST_CARDS = {
    "4242424242424242",
    "4111111111111111",
    "5555555555554444",
    "378282246310005",
}

SECRET_CMD_PATTERNS = [
    (
        re.compile(
            r"\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain|export)\b"
        ),
        "macOS Keychain secret access detected",
    ),
    (
        re.compile(r"\bop\s+(?:read|item|inject|run|signin)\b"),
        "1Password CLI (`op`) secret access detected",
    ),
    (
        re.compile(r"\bbw\s+(?:get|unlock|export)\b"),
        "Bitwarden CLI (`bw`) secret access detected",
    ),
    (
        re.compile(r"Library/Keychains"),
        "macOS Keychain path access detected",
    ),
    (
        re.compile(r"/\.ssh(?:/|\b)"),
        "SSH directory/key access detected",
    ),
    (
        re.compile(r"/\.aws/credentials\b"),
        "AWS credentials file access detected",
    ),
    (
        re.compile(r"/\.gnupg(?:/|\b)"),
        "GnuPG keyring directory access detected",
    ),
]

PIPE_EXEC_RE = re.compile(
    r"\b(?:curl|wget)\b[^;\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python3?|perl|ruby|node)\b"
)

CMD_SPLIT_RE = re.compile(r"(?:&&|\|\||;|\n)")
JS_INSTALL_RE = re.compile(r"\b(?:npm|pnpm)\s+(?:install|i|ci|add)\b")
YARN_INSTALL_RE = re.compile(r"\byarn(?:\s*$|\s+(?:install|add)\b)")
PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b")
PIP_RISKY_FLAG_RE = re.compile(r"(?:git\+|https?://|--no-build-isolation|(?:^|\s)-e\s)")


def force_ask(reason):
    """Return a forced-approval PreToolUse decision."""
    return {"decision": "force_ask", "reason": f"[Personal Guardrails] {reason}"}


def check_run_command(command_line):
    """Inspect shell command lines for secret reads, piped downloads, and install scripts."""
    for pat, message in SECRET_CMD_PATTERNS:
        if pat.search(command_line):
            return force_ask(f"{message}. Explicit confirmation required.")

    if PIPE_EXEC_RE.search(command_line):
        return force_ask("Remote download piped directly to an interpreter. Explicit confirmation required.")

    for raw_seg in CMD_SPLIT_RE.split(command_line):
        seg = raw_seg.strip()
        if not seg:
            continue
        if (JS_INSTALL_RE.search(seg) or YARN_INSTALL_RE.search(seg)) and not re.search(
            r"--ignore-scripts\b", seg
        ):
            return force_ask(
                "Package install runs lifecycle scripts (missing `--ignore-scripts`). Confirm before executing."
            )
        if PIP_INSTALL_RE.search(seg) and PIP_RISKY_FLAG_RE.search(seg):
            return force_ask(
                "pip install references a remote URL, VCS repo, editable path, or disabled build isolation. Confirm before executing."
            )

    return None


def is_valid_iban(candidate):
    """Verify country code, official length, alphanumeric payload, and ISO 13616 Mod-97."""
    compact = re.sub(r"[ -]", "", candidate).upper()
    if len(compact) < 5:
        return False
    country = compact[:2]
    expected_len = IBAN_LENGTHS.get(country)
    if expected_len is None or len(compact) != expected_len:
        return False
    if not compact[2:4].isdigit() or not compact[4:].isalnum():
        return False

    rearranged = compact[4:] + compact[:4]
    numeric_str = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    return int(numeric_str) % 97 == 1


def is_valid_luhn_card(candidate):
    """Verify payment card candidate passes Luhn and is not a standard test card."""
    digits = re.sub(r"[ -]", "", candidate)
    if not (13 <= len(digits) <= 19) or digits in TEST_CARDS:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


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
    """Load optional user-configured substrings, regexes, and sha256_tokens."""
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
    """Check a string against optional substrings, regexes, and salted/unsalted sha256 tokens."""
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
        words = re.findall(r"[a-z0-9]+", lower_text)
        candidates.update(words)
        for i in range(len(words) - 1):
            candidates.add(f"{words[i]} {words[i + 1]}")
        for token in re.findall(r"[^\s,;:\"'(){}\[\]<>]+", lower_text):
            candidates.add(token)
        for num_cand in re.findall(r"\+?[0-9][0-9 .-]{4,}[0-9]", text):
            digits = re.sub(r"[^0-9]", "", num_cand)
            if len(digits) >= 6:
                candidates.add(digits)
        for digits in re.findall(r"[0-9]{6,}", text):
            candidates.add(digits)

        for cand in candidates:
            if sha256_hex(cand) in sha256_tokens:
                return True

    return False


def check_sensitive_strings(args):
    """Scan all string arguments for IBANs, payment cards, or protected identifiers."""
    strings = []
    collect_strings(args, strings)
    if not strings:
        return None

    substrings, regexes, sha256_tokens = load_protected_identifiers()

    for text in strings:
        for match in IBAN_CANDIDATE_RE.finditer(text):
            if is_valid_iban(match.group(0)):
                return force_ask(
                    "Valid IBAN detected in tool arguments. Confirm origin audit and user approval before proceeding."
                )

        for match in CARD_CANDIDATE_RE.finditer(text):
            if is_valid_luhn_card(match.group(0)):
                return force_ask(
                    "Valid payment card number detected in tool arguments. Confirm origin audit and user approval before proceeding."
                )

        if check_protected_identifiers(text, substrings, regexes, sha256_tokens):
            return force_ask(
                "Protected personal identifier detected in tool arguments. Confirm origin audit and user approval before proceeding."
            )

    return None


def main():
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    tool_call = payload.get("toolCall") or {}
    tool_name = str(tool_call.get("name") or "").lower()
    args = tool_call.get("args")

    if tool_name == "run_command" and isinstance(args, dict):
        cmd = str(args.get("CommandLine") or "")
        verdict = check_run_command(cmd)
        if verdict is not None:
            print(json.dumps(verdict))
            return

    sensitive_verdict = check_sensitive_strings(args)
    if sensitive_verdict is not None:
        print(json.dumps(sensitive_verdict))
        return

    print(json.dumps({"decision": "allow"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            json.dumps(
                {
                    "decision": "ask",
                    "reason": f"[Personal Guardrails] Hook check error ({type(exc).__name__}); please confirm.",
                }
            )
        )
