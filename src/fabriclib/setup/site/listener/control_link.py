import itertools
import json
import os
import threading


class ControlLink:
    """The listener's end of the socket only it and setup can use (manual 1.3.6.3), JSON lines."""

    def __init__(self, sock, state):
        """Purpose: wrap the inherited socket.
        Inputs:  sock — the listener's end of setup's socketpair; state — SiteState, or None until setup's hello.
        Returns: None.
        Fails:   never.
        Feeds:   listener/site_main."""
        self.sock, self.state = sock, state
        self.reader = sock.makefile("r", encoding="utf-8")
        self.lock = threading.Lock()
        self.ids = itertools.count(1)
        self.waiting = {}

    def read_hello(self):
        """Purpose: setup's first message.
        Inputs:  none.
        Returns: dict.
        Fails:   ValueError when setup closed before saying it.
        Feeds:   listener/site_main."""
        line = self.reader.readline()
        if not line:
            raise ValueError("setup closed the link before its hello")
        return json.loads(line)

    def send(self, message):
        """Purpose: tell setup something.
        Inputs:  message — dict.
        Returns: None.
        Fails:   OSError when setup has gone: the process then ends with the link (run).
        Feeds:   listener/request_handler."""
        data = (json.dumps(message) + "\n").encode()
        with self.lock:
            self.sock.sendall(data)

    def request(self, message, timeout=30):
        """Purpose: ask setup something and wait for its answer: the code and the check are setup's to judge.
        Inputs:  message — dict; timeout — seconds.
        Returns: setup's reply (dict); {} when none came in time.
        Fails:   OSError as send.
        Feeds:   listener/request_handler."""
        number, done, box = next(self.ids), threading.Event(), {}
        self.waiting[number] = (done, box)
        self.send({**message, "id": number})
        done.wait(timeout)
        self.waiting.pop(number, None)
        return box

    def run(self):
        """Purpose: read setup's messages until it closes the link, then end the whole process: a listener outliving
                 setup would hold the port with nobody behind it.
        Inputs:  none.
        Returns: never returns.
        Fails:   never; any end of the link ends the process.
        Feeds:   listener/site_main."""
        try:
            for line in self.reader:
                message = json.loads(line)
                if message.get("t") == "reply":
                    done, box = self.waiting.get(message.get("id"), (None, None))
                    if done:
                        box.update(message)
                        done.set()
                else:
                    self.state.apply(message)
        finally:
            os._exit(0)
