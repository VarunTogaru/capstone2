from collections.abc import Sequence
from typing import Optional

ALLOWED_TIMING_FLAGS = {f"-T{level}" for level in range(6)}
ALLOWED_SCRIPT_CATEGORIES = {"default", "safe", "vuln"}

ALLOWED_FLAGS = {
    "-sS",
    "-sT",
    "-sU",
    "-sV",
    "-A",
    "-O",
    "-Pn",
    "-n",
    "--open",
    "--reason",
    "--traceroute",
}

ALLOWED_VALUE_FLAGS = {
    "-p",
    "--top-ports",
    "--script",
}

BLOCKED_FLAGS = {
    "-D",
    "-S",
    "-e",
    "-g",
    "-f",
    "-b",
    "--source-port",
    "--proxies",
    "--data",
    "--data-string",
    "--data-length",
    "--ip-options",
    "--ttl",
    "--spoof-mac",
    "--badsum",
    "--scanflags",
    "-sI",
    "--mtu",
    "-oN",
    "-oX",
    "-oS",
    "-oG",
    "-oA",
    "--stylesheet",
    "--webxml",
    "--no-stylesheet",
}


def _is_target_token(token: str) -> bool:
    return bool(token) and not token.startswith("-")


def _validate_script_value(value: str) -> Optional[str]:
    categories = [part.strip() for part in value.split(",") if part.strip()]
    if not categories:
        return "Script value cannot be empty"
    for category in categories:
        if category not in ALLOWED_SCRIPT_CATEGORIES:
            return f"Script category '{category}' is not allowed in privileged mode"
    return None


def validate_privileged_command(args: Sequence[str]) -> list[str]:
    errors: list[str] = []
    if not args or args[0] != "nmap":
        return ["Privileged command must start with nmap"]

    index = 1
    while index < len(args):
        token = args[index]

        # Allow target token as trailing argument.
        if _is_target_token(token) and index == len(args) - 1:
            break

        # Allow forced XML stdout segment.
        if token == "-oX":
            if index + 1 >= len(args) or args[index + 1] != "-":
                errors.append("Privileged scan must keep XML output to stdout")
            index += 2
            continue

        # Handle --script=<value> inline.
        if token.startswith("--script="):
            script_value = token.split("=", 1)[1]
            script_error = _validate_script_value(script_value)
            if script_error:
                errors.append(script_error)
            index += 1
            continue

        if token in BLOCKED_FLAGS:
            errors.append(f"Flag '{token}' is blocked in privileged mode")
            index += 1
            continue

        if token in ALLOWED_TIMING_FLAGS or token in ALLOWED_FLAGS:
            index += 1
            continue

        if token in ALLOWED_VALUE_FLAGS:
            if index + 1 >= len(args):
                errors.append(f"Flag '{token}' requires a value")
                index += 1
                continue
            value = args[index + 1]
            if value.startswith("-"):
                errors.append(f"Flag '{token}' requires a value")
            elif token == "--script":
                script_error = _validate_script_value(value)
                if script_error:
                    errors.append(script_error)
            index += 2
            continue

        errors.append(f"Flag '{token}' is not allowed in privileged mode")
        index += 1

    return errors
