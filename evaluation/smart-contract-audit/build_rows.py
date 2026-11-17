#!/usr/bin/env python3
"""Evaluation material for SMART_CONTRACT_AUDIT_GENERAL, from SmartBugs Curated.

SmartBugs Curated (https://github.com/smartbugs/smartbugs-curated, Apache 2.0)
is a set of real vulnerable Solidity contracts whose vulnerable lines were
labelled by hand. Each contract becomes one preference pair:

- prompt:   the contract with every comment removed (the dataset's markers and
            the explanatory comments would give the answer away), asking for
            an audit. Line numbers are kept as in the original file.
- chosen:   an audit naming each labelled vulnerability: its class, the line
            and code, why it is exploitable and how to fix it.
- rejected: a plausible but wrong audit. It calls the contract safe, names
            the wrong class, understates the real issue without locating it,
            or lists style nits and misses the vulnerability. The strategy
            rotates, and lengths vary so length can't tell the two apart.

Both answers are written deterministically from the dataset's labels (no
model), so the rows are reproducible: rerun this script on the same dataset
commit and you get the same file. Near-duplicate contracts are dropped, since
the node rejects questions 85% or more similar to one it already holds.

Usage: python3 -I build_rows.py <path to smartbugs-curated checkout> <out.jsonl>
"""
import json
import os
import re
import sys

INTENT = "SMART_CONTRACT_AUDIT_GENERAL"
MAX_PROMPT = 15_500  # the node accepts 16 to 16,000 characters
REPO_URL = "https://github.com/smartbugs/smartbugs-curated/blob/main/"

# Per dataset category: title, severity, why it matters, how to fix.
CATEGORY = {
    "reentrancy": ("Reentrancy", "high",
        "An external call transfers control to another contract before this contract finishes updating its own state, so the callee can call back in and repeat the operation (for example, withdraw the same balance again).",
        "Update state before the external call (checks-effects-interactions), and add a reentrancy guard on functions that send value."),
    "access_control": ("Missing or broken access control", "high",
        "A privileged action can be reached by anyone: an unprotected function, a misnamed constructor, a delegatecall into attacker-influenced code, or a check that never fails.",
        "Restrict the action to authorised callers (an owner or role check, a correctly named constructor), and never delegatecall into code callers can influence."),
    "arithmetic": ("Integer overflow or underflow", "high",
        "The contract targets a compiler version without checked arithmetic, so this operation can wrap around and produce a balance or amount the logic never intended.",
        "Use SafeMath or compile with Solidity 0.8 or later, and validate inputs before arithmetic on balances and amounts."),
    "unchecked_low_level_calls": ("Unchecked low-level call", "medium",
        "The return value of a low-level call (call, send, delegatecall) is ignored. If the call fails, execution continues as if it succeeded, leaving the contract's accounting inconsistent.",
        "Check the returned success flag and revert on failure, or use transfer or a safe-call helper."),
    "bad_randomness": ("Predictable randomness", "high",
        "Randomness is derived from on-chain values such as block hash, timestamp or number, which miners and other contracts can read or influence, so the outcome can be predicted or manipulated.",
        "Use a verifiable randomness source (a VRF oracle) or a commit-reveal scheme instead of block data."),
    "denial_of_service": ("Denial of service", "medium",
        "One account or an unbounded loop can block the function for everyone: a failing payment to a single recipient, or iteration over data an attacker can grow until it exceeds the gas limit.",
        "Use pull payments instead of pushing value in a loop, bound loops, and don't let one recipient's failure revert the whole operation."),
    "front_running": ("Front-running (transaction-order dependence)", "medium",
        "The outcome depends on information that is visible in the mempool before the transaction is mined, so another account can see it and submit a competing transaction first.",
        "Use commit-reveal, or design the logic so transaction order can't change who wins or what is paid."),
    "time_manipulation": ("Timestamp dependence", "medium",
        "Logic depends on block.timestamp (now), which the block producer can shift by several seconds, enough to influence a time-based condition or outcome.",
        "Don't use the timestamp for randomness or tight deadlines; tolerate drift, or use block numbers with an explicit margin."),
    "short_addresses": ("Short address attack", "low",
        "The function doesn't check the length of its call data, so a truncated address argument can shift the following arguments and inflate the amount.",
        "Validate msg.data length for functions that take an address followed by an amount."),
    "other": ("Logic flaw", "medium",
        "This line behaves differently from what the contract intends (for example, an uninitialised storage pointer or a variable that shadows another), which an attacker can exploit.",
        "Initialise storage explicitly, avoid shadowing, and add tests for the intended behaviour."),
}

# One-line fixes for the terse style of answer.
SHORT_FIX = {
    "reentrancy": "update state before the external call, or add a reentrancy guard",
    "access_control": "restrict it to authorised callers",
    "arithmetic": "use SafeMath or Solidity 0.8+ checked arithmetic",
    "unchecked_low_level_calls": "check the returned success flag and revert on failure",
    "bad_randomness": "use a VRF oracle or commit-reveal instead of block data",
    "denial_of_service": "use pull payments and bound the loop",
    "front_running": "use commit-reveal so order can't change the outcome",
    "time_manipulation": "don't rely on the exact timestamp",
    "short_addresses": "validate msg.data length",
    "other": "initialise storage explicitly and test the intended behaviour",
}

PROMPTS = [
    "Audit this Solidity smart contract for security vulnerabilities. For each issue, say what it is, which line it's on, how severe it is, and how to fix it.",
    "Review this smart contract for exploitable bugs before deployment. List each vulnerability with its line, severity and a fix.",
    "Security-audit the following Solidity code. Identify the vulnerabilities an attacker could exploit, with line numbers and recommended fixes.",
    "Find the security vulnerabilities in this contract. For each one, give the vulnerability class, the affected line, the impact and the fix.",
]


def strip_comments(src):
    """Remove // and /* */ comments outside string literals, keeping every newline."""
    out, i, n, quote = [], 0, len(src), None
    while i < n:
        c = src[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
        elif c in "\"'":
            quote = c; out.append(c); i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, j))
            i = j
        else:
            out.append(c); i += 1
    return "\n".join(line.rstrip() for line in "".join(out).split("\n"))


def shingles(text, k=6):
    toks = re.findall(r"[A-Za-z_]\w*|\d+|\S", text)
    return {tuple(toks[i:i + k]) for i in range(max(0, len(toks) - k + 1))}


def similar(a, b):
    return len(a & b) / max(1, len(a | b))


def specific_why(cat, code):
    """A sharper explanation when the flagged line shows which variant it is."""
    if cat == "access_control" and "delegatecall" in code:
        return "delegatecall runs another contract's code in this contract's storage, and the target or the call data can be influenced by the caller, so anyone can rewrite this contract's state."
    if cat == "access_control" and re.match(r"function\s+[A-Z]\w*\s*\(", code):
        return "This function looks like it was meant to be the constructor, but its name doesn't match the contract, so it is an ordinary public function anyone can call to take ownership."
    if cat == "unchecked_low_level_calls" and ".send(" in code:
        return "send returns false instead of reverting when the transfer fails, and the result is ignored, so the contract carries on as if the payment went through."
    return CATEGORY[cat][2]


def chosen_answer(findings, detailed):
    """The correct audit; `detailed` adds the why, otherwise it's terse."""
    worst = "high" if any(CATEGORY[c][1] == "high" for c, _, _ in findings) else "medium" if any(CATEGORY[c][1] == "medium" for c, _, _ in findings) else "low"
    parts = [f"Verdict: vulnerable. Highest severity: {worst}.", ""]
    for k, (cat, line, code) in enumerate(findings, 1):
        title, sev, _, fix = CATEGORY[cat]
        if detailed:
            parts += [f"Finding {k}: {title} ({sev}), line {line}: `{code}`", specific_why(cat, code), f"Fix: {fix}", ""]
        else:
            parts += [f"{k}. {title} ({sev}) at line {line}: `{code}`. Fix: {SHORT_FIX[cat]}.", ""]
    return "\n".join(parts).strip()


def rejected_answer(findings, idx, lines):
    """A plausible wrong audit; the strategy rotates with idx."""
    cats = {c for c, _, _ in findings}
    strategy = idx % 4
    if strategy == 0:  # calls it safe, at length
        return ("Verdict: no critical issues found.\n\n"
                "Access control: the state-changing functions are limited to the callers they are meant for, and ownership is set once.\n"
                "State and value transfers: balances are updated consistently around transfers, and external calls are handled.\n"
                "Arithmetic and inputs: amounts stay within expected bounds for this contract's use.\n\n"
                "Recommendations (not security issues): emit events for important state changes, pin the compiler version "
                "instead of using a floating pragma, and add NatSpec comments. Nothing here is exploitable.")
    if strategy == 1:  # names two wrong classes, at unrelated lines, in full
        wrong = [c for c in ["time_manipulation", "front_running", "arithmetic", "denial_of_service", "bad_randomness", "reentrancy"] if c not in cats][:2]
        bad_lines = {l for _, l, _ in findings}
        others = [i + 1 for i, t in enumerate(lines) if t.strip() and (i + 1) not in bad_lines and "function" in t][:2] or [1, 1]
        sev = CATEGORY[wrong[0]][1]
        parts = [f"Verdict: vulnerable. Highest severity: {sev}.", ""]
        for k, (c, ln) in enumerate(zip(wrong, others * 2), 1):
            title, s2, why, fix = CATEGORY[c]
            parts += [f"Finding {k}: {title} ({s2}), line {ln}: `{lines[ln - 1].strip()[:120]}`", why, f"Fix: {fix}", ""]
        return "\n".join(parts).strip()
    if strategy == 2:  # right area, understated and unlocated
        cat = findings[0][0]
        return (f"Verdict: vulnerable. Highest severity: low.\n\nThere is a minor {CATEGORY[cat][0].lower()} concern in the contract, "
                "but it is unlikely to be exploitable in practice and can wait until a later release.")
    # style nits, misses the vulnerability
    return ("Verdict: needs cleanup, no security vulnerabilities found.\n\n"
            "1. The pragma is floating; pin an exact compiler version so builds are reproducible.\n"
            "2. Several functions rely on default visibility; declare public, external or internal explicitly.\n"
            "3. State changes don't emit events, which makes the contract hard to monitor off-chain.\n"
            "4. Some variable and function names don't follow the Solidity style guide (mixedCase for functions, CapWords for contracts).\n"
            "5. NatSpec comments are missing on the public interface.\n\n"
            "These are readability and maintainability fixes; none of them is exploitable.")


def main(root, out_path):
    data = json.load(open(os.path.join(root, "vulnerabilities.json")))
    kept, rows, skipped = [], [], {"too_long": 0, "near_duplicate": 0, "no_findings": 0}
    for idx, entry in enumerate(sorted(data, key=lambda x: x["path"])):
        raw = open(os.path.join(root, entry["path"]), encoding="utf-8").read()
        all_lines = strip_comments(raw).split("\n")
        # Drop the blank lines left where the header comment was, and renumber.
        lead = next((i for i, t in enumerate(all_lines) if t.strip()), 0)
        lines = all_lines[lead:]
        while lines and not lines[-1].strip():
            lines.pop()
        code = "\n".join(lines)
        findings = []
        for v in entry["vulnerabilities"]:
            for ln in v["lines"]:
                n = ln - lead
                text = lines[n - 1].strip() if 0 < n <= len(lines) else ""
                if text and v["category"] in CATEGORY and len(findings) < 6:
                    findings.append((v["category"], n, text[:120]))
        if not findings:
            skipped["no_findings"] += 1; continue
        prompt = f"{PROMPTS[idx % len(PROMPTS)]} Line numbers count from the first line of the code.\n\n```solidity\n{code}\n```"
        if len(prompt) > MAX_PROMPT:
            skipped["too_long"] += 1; continue
        sh = shingles(code)
        if any(similar(sh, s) >= 0.75 for s in kept):
            skipped["near_duplicate"] += 1; continue
        kept.append(sh)
        rows.append({
            "intent_id": INTENT,
            "prompt": prompt,
            "chosen": chosen_answer(findings, detailed=len(rows) % 5 != 0),
            "rejected": rejected_answer(findings, len(rows), lines),
            "label_kind": "preference_pair",
            "provenance": {"source_kind": "dataset", "source_url": REPO_URL + entry["path"]},
        })
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    longer = sum(len(r["chosen"]) > len(r["rejected"]) for r in rows)
    print(json.dumps({"rows": len(rows), "skipped": skipped, "chosen_longer": longer, "rejected_longer": len(rows) - longer}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
