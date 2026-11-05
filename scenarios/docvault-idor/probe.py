"""Black-box security regression probe for the docvault IDOR finding.

Runs in its own container, separate from the application under test, and talks to
it only over HTTP. It imports nothing from the target, so patched application code
cannot influence this process except through HTTP responses.

Prints exactly one JSON object on stdout.
"""

import json
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/")
ALICE = "tok-alice-acme"  # tenant 1
CAROL = "tok-carol-acme"  # tenant 1
BOB = "tok-bob-globex"  # tenant 2

# (actor token, document id, document tenant marker in body, should be readable)
CASES = [
    ("cross_tenant:bob->doc1", BOB, 1, "ACME-INTERNAL", False),
    ("cross_tenant:bob->doc2", BOB, 2, "ACME-INTERNAL", False),
    ("cross_tenant:alice->doc3", ALICE, 3, "GLOBEX-INTERNAL", False),
    ("legit:alice->doc1", ALICE, 1, "ACME-INTERNAL", True),
    ("legit:carol->doc1", CAROL, 1, "ACME-INTERNAL", True),
    ("legit:bob->doc3", BOB, 3, "GLOBEX-INTERNAL", True),
]


def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("X-User-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")


def wait_healthy(deadline_s=20.0):
    start = time.monotonic()
    last = None
    while time.monotonic() - start < deadline_s:
        try:
            status, _ = get("/health")
            if status == 200:
                return True, None
            last = f"health status {status}"
        except Exception as e:  # connection refused while the server boots
            last = type(e).__name__
        time.sleep(0.25)
    return False, last


def main():
    healthy, err = wait_healthy()
    if not healthy:
        print(json.dumps({"healthy": False, "error": f"app did not become healthy: {err}", "checks": []}))
        return
    checks = []
    for name, token, doc_id, marker, should_read in CASES:
        try:
            status, body = get(f"/documents/{doc_id}", token)
            content_returned = status == 200 and marker in body
            if should_read:
                outcome = "pass" if content_returned else "fail"
            else:
                outcome = "fail" if content_returned or status == 200 else "pass"
            checks.append({"name": name, "kind": "legitimate" if should_read else "unauthorized",
                           "status_code": status, "content_returned": content_returned, "outcome": outcome})
        except Exception as e:
            checks.append({"name": name, "kind": "legitimate" if should_read else "unauthorized",
                           "status_code": None, "content_returned": False, "outcome": "error",
                           "error": type(e).__name__})
    print(json.dumps({"healthy": True, "error": None, "checks": checks}))


if __name__ == "__main__":
    main()
