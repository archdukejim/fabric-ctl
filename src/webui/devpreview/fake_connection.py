import json
import urllib.parse

from webui.agentclient import connection
from webui.devpreview.fake_agent import fake_agent


class _Reply:
    """A fake agent's reply, read the way call_agent reads an http.client response."""

    def __init__(self, status, obj):
        """Purpose: Hold one reply.
        Inputs:  status — int HTTP status; obj — the JSON-able answer.
        Returns: None.
        Fails:   never.
        Feeds:   FakeConnection.getresponse."""
        self.status = status
        self._body = json.dumps(obj).encode()

    def read(self):
        """Purpose: The reply's body.
        Inputs:  none.
        Returns: bytes (JSON).
        Fails:   never.
        Feeds:   connection.call_agent."""
        return self._body


class FakeConnection:
    """Stands in for the agent's unix-socket connection in the dev preview: every agent call the real routes make is
    answered in this process from the preview's in-memory sample data (fake_agent), so no fabric-agent runs."""

    state = None
    who = {"user": "dev", "perms": ()}

    def __init__(self, timeout=30):
        """Purpose: One fake connection (what connection._UnixConnection(timeout) makes).
        Inputs:  timeout — ignored.
        Returns: None.
        Fails:   never.
        Feeds:   connection.call_agent."""
        self._reply = None

    def request(self, method, path, body=None, headers=None):
        """Purpose: Answer one agent request from memory.
        Inputs:  method — "GET" or "POST"; path — "/v1/..." with quoted segments; body — JSON bytes or None; headers
                 — ignored (the preview has no token: its person is FakeConnection.who).
        Returns: None; the reply is kept for getresponse.
        Fails:   never (fake_agent answers every refusal as a status).
        Feeds:   connection.call_agent."""
        route = [urllib.parse.unquote(p) for p in urllib.parse.urlsplit(path).path.strip("/").split("/")][1:]
        data = json.loads(body) if body else {}
        self._reply = _Reply(*fake_agent(self.state, self.who, method, route, data))

    def getresponse(self):
        """Purpose: The reply to the last request.
        Inputs:  none.
        Returns: _Reply.
        Fails:   never.
        Feeds:   connection.call_agent."""
        return self._reply

    def close(self):
        """Purpose: Nothing to close.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   connection.call_agent."""

    @classmethod
    def install(cls, state, who):
        """Purpose: Answer every agent call of this process from the preview's state, as the preview's person.
        Inputs:  state — the DevState; who — {"user", "perms"} (the bundle given with --as).
        Returns: None; webui.agentclient.connection now makes FakeConnections.
        Fails:   never.
        Feeds:   devserver.py (once, at start)."""
        cls.state, cls.who = state, who
        connection._UnixConnection = cls
