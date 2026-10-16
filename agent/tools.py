
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = (ROOT / "sandbox").resolve()
DATA_DIR = ROOT / "data"


def _safe_path(path):
    """Resolve a path and reject paths outside sandbox/."""
    candidate = (SANDBOX_DIR / path).resolve()

    try:
        candidate.relative_to(SANDBOX_DIR)
    except ValueError:
        raise ValueError("Access denied: path is outside sandbox")

    return candidate


def read_file(path):
    """Read a UTF-8 text file inside sandbox/."""
    file_path = _safe_path(path)

    if not file_path.is_file():
        raise FileNotFoundError("File not found inside sandbox")

    return file_path.read_text(encoding="utf-8")


def run_shell(command):
    """Run one explicitly allowlisted command inside sandbox/."""
    allowed_commands = {
        ("python", "--version"),
        ("python3", "--version"),
        ("git", "--version"),
    }

    if not isinstance(command, (list, tuple)):
        raise ValueError("Command must be a list of arguments")

    command = tuple(command)

    if command not in allowed_commands:
        raise ValueError("Command not allowed")

    result = subprocess.run(
        list(command),
        cwd=SANDBOX_DIR,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
        check=False,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def http_request(method, url):
    """Simulate an HTTP request by writing it to a JSON log."""
    method = method.upper()

    if method not in {"GET", "POST", "PUT", "DELETE"}:
        raise ValueError("HTTP method not allowed")

    parsed_url = urlparse(url)

    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("Invalid HTTP URL")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log_path = DATA_DIR / "fake_http.log"

    entry = {
        "method": method,
        "url": url,
        "simulated": True,
    }

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")

    return {
        "status": "simulated",
        "message": "Request logged; no network request was sent.",
        "request": entry,
    }
