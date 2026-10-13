# fabriclib/radius/coa

Disconnect and CoA (RFC 5176) from fabric-agent to the switch of an 802.1X session (manual 1.11.1.4, decision
2.1.11.6), for the vendors whose profile has them.

| File | What |
|---|---|
| `attributes.py` | RADIUS codes, attribute numbers, Error-Cause names, and the encoders for text, IPv4, integer and Cisco-AVPair values |
| `build_radius_packet.py` | A Disconnect-Request or CoA-Request signed as RFC 5176 says, with a Message-Authenticator |
| `read_radius_reply.py` | Check the switch's answer (identifier, code, Response Authenticator, Message-Authenticator) and read ACK / NAK and its Error-Cause |
| `send_coa.py` | Send one request over UDP and wait for a valid answer (three tries) |
| `coa_session.py` | Disconnect, re-authenticate or bounce a session: refused with why for a vendor without CoA, a closed session, a NAS outside the client; audited |
