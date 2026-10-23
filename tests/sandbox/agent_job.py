"""Inside the sandbox, as root: run one fabric-agent job through its socket and wait for it (2.1.8.3): what the web
console's Run doctor and Updates do. Prints the job's state and result as JSON.
    python3 agent_job.py doctor | images <update|rollback> <service>
    python3 agent_job.py post <path> '<json body>'     one route answered at once (e.g. /v1/local-admin/ssh)
"""
import json
import socket
import sys
import time

SOCK = "/opt/webui/agent/agent.sock"


def call(method, path, body=None):
    """One request to the agent as root (the actor named in the body), its JSON answer."""
    data = json.dumps(body or {}).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(SOCK)
        s.sendall(f"{method} {path} HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n"
                  .encode() + data)
        reply = b""
        while chunk := s.recv(65536):
            reply += chunk
    return json.loads(reply.split(b"\r\n\r\n", 1)[1])


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "post":
        print(json.dumps(call("POST", sys.argv[2], {"actor": "sandbox", **json.loads(sys.argv[3])})))
        sys.exit(0)
    if sys.argv[1:] == ["doctor"]:
        started = call("POST", "/v1/jobs/doctor", {"actor": "sandbox"})
    elif len(sys.argv) == 4 and sys.argv[1] == "images":
        started = call("POST", "/v1/jobs/images", {"actor": "sandbox", "action": sys.argv[2], "service": sys.argv[3]})
    else:
        sys.exit(__doc__)
    for _ in range(300):
        job = call("GET", f"/v1/jobs/{started['id']}")
        if job["state"] != "running":
            break
        time.sleep(1)
    print(json.dumps(job))
