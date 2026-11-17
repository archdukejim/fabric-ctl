#!/usr/bin/env python3
"""The host's half of the finish's check (manual 1.3.6.6) against a real DNS answer over UDP and a real TLS console, with
fabric's root as the only trust. Each failure must say which of the two failed.
    python3 tests/setup/site/check_console_test.py"""
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import check, finish  # noqa: E402

from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.site.check_console import check_console  # noqa: E402

NAME, IP = "fabric-ctl.lan.example", "127.0.0.1"


def openssl(*args):
    subprocess.run(["openssl", *args], capture_output=True, check=True)


def make_ca(folder, stem):
    """A root and a leaf for the console's name. Returns (root path, leaf path, key path)."""
    root, root_key = f"{folder}/{stem}-root.crt", f"{folder}/{stem}-root.key"
    leaf, key, csr, ext = f"{folder}/{stem}.crt", f"{folder}/{stem}.key", f"{folder}/{stem}.csr", f"{folder}/{stem}.ext"
    curve = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes")
    # a CA with keyUsage, as fabric's own root has (init_pki): Python 3.13+ verifies strictly (VERIFY_X509_STRICT)
    # and refuses a CA without it (2.3.1.56)
    openssl("req", "-x509", *curve, "-keyout", root_key, "-out", root, "-days", "2", "-subj", f"/CN={stem} root",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", *curve, "-keyout", key, "-out", csr, "-subj", f"/CN={NAME}")
    with open(ext, "w") as f:
        f.write(f"subjectAltName=DNS:{NAME}\n")
    openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key, "-CAcreateserial", "-days", "1", "-extfile", ext,
            "-out", leaf)
    return root, leaf, key


def dns_server(answer):
    """A real DNS server for one name, on UDP: `answer` is the address it gives. Returns (socket, port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, 0))

    def serve():
        while True:
            try:
                query, peer = sock.recvfrom(512)
            except OSError:
                return
            record = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(answer)
            sock.sendto(query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + record, peer)
    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


def console(leaf, key):
    """A real TLS console: accepts and closes. Returns (socket, port)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(leaf, key)
    sock = socket.create_server((IP, 0))

    def serve():
        while True:
            try:
                raw, _ = sock.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(raw, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


with tempfile.TemporaryDirectory() as base:
    ctx = SetupContext(deploy_base=base)
    ctx.vars = {"hostname_mgr": NAME, "host_ip": IP}
    os.makedirs(ctx.path("nginx", "www", "certs"), exist_ok=True)
    root, leaf, key = make_ca(base, "fabric")
    with open(root) as f, open(ctx.path("nginx", "www", "certs", "root-ca.crt"), "w") as out:
        out.write(f.read())
    _other_root, other_leaf, other_key = make_ca(base, "other")
    dns_right, right_port = dns_server(IP)
    dns_wrong, wrong_port = dns_server("192.0.2.9")
    served, https_port = console(leaf, key)
    other, other_port = console(other_leaf, other_key)

    problem = check_console(ctx, timeout=2, dns_port=right_port, https_port=https_port)
    check("the name answers with this host and the console with fabric's certificate: no problem", problem == "", problem)

    problem = check_console(ctx, timeout=2, dns_port=wrong_port, https_port=https_port)
    check("DNS answering another address: says it is DNS, and what it answered", "192.0.2.9" in problem and "DNS" in problem, problem)

    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind((IP, 0))
    problem = check_console(ctx, timeout=1, dns_port=silent.getsockname()[1], https_port=https_port)
    check("DNS not answering: says it is DNS", "DNS" in problem and NAME in problem, problem)
    silent.close()

    problem = check_console(ctx, timeout=2, dns_port=right_port, https_port=other_port)
    check("another CA's certificate on the console: refused, never accepted", "certificate" in problem and problem != "", problem)

    closed = socket.socket()
    closed.bind((IP, 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    problem = check_console(ctx, timeout=2, dns_port=right_port, https_port=closed_port)
    check("the console not answering: says it is the console", "console" in problem, problem)

    for sock in (dns_right, dns_wrong, served, other):
        sock.close()

sys.exit(finish("check_console_test"))
