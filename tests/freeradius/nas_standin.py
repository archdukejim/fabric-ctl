"""A stand-in for a switch's CoA listener (RFC 5176), for the tests: no real Cisco switch is available (2.3.11.5).
Written from the RFC, not from fabric's code: it checks the Request Authenticator and Message-Authenticator of what
it receives and answers ACK, or NAK with an Error-Cause, signed with the shared secret.

    nas = NasStandin(secret, host="127.0.0.1", port=0, answer="ack")   # "ack", "nak", "silent", "badsig"
    nas.port; nas.received  -> [{"code", "attrs": {type: [bytes]}, "valid": bool}]; nas.stop()
"""
import hashlib
import hmac
import socket
import struct
import threading


class NasStandin:
    def __init__(self, secret, host="127.0.0.1", port=0, answer="ack"):
        self.secret, self.answer, self.received = secret.encode(), answer, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _parse(self, data):
        attrs, pos = {}, 20
        while pos + 2 <= len(data):
            kind, size = data[pos], data[pos + 1]
            if size < 2:
                break
            attrs.setdefault(kind, []).append(data[pos + 2:pos + size])
            pos += size
        return attrs

    def _valid(self, data):
        expected = hashlib.md5(data[:4] + b"\0" * 16 + data[20:] + self.secret).digest()
        if expected != data[4:20]:
            return False
        pos = 20
        while pos + 2 <= len(data):
            kind, size = data[pos], data[pos + 1]
            if kind == 80:
                zeroed = data[:4] + b"\0" * 16 + data[20:pos + 2] + b"\0" * 16 + data[pos + size:]
                return hmac.new(self.secret, zeroed, hashlib.md5).digest() == data[pos + 2:pos + size]
            pos += max(size, 2)
        return False                      # fabric always sends one

    def _reply(self, request, nak):
        code = {40: 42 if nak else 41, 43: 45 if nak else 44}[request[0]]
        attrs = struct.pack("!BBI", 101, 6, 503) if nak else b""
        length = 20 + len(attrs)
        head = struct.pack("!BBH", code, request[1], length)
        auth = hashlib.md5(head + request[4:20] + attrs + self.secret).digest()
        if self.answer == "badsig":
            auth = bytes(16)
        return head + auth + attrs

    def _serve(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            valid = self._valid(data)
            self.received.append({"code": data[0], "attrs": self._parse(data), "valid": valid})
            if self.answer == "silent":
                continue
            self.sock.sendto(self._reply(data, nak=self.answer == "nak" or not valid), peer)

    def stop(self):
        self.running = False
        self.thread.join(2)
        self.sock.close()
