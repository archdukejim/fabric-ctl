import ssl


def _note_name(state):
    """Purpose: a TLS callback recording the name each client's hello asks for: that the hello reached this host is the
             finish's proof that the name resolves here, even when the client then refuses the certificate (1.3.6.6).
    Inputs:  state — SiteState.
    Returns: callable(socket, name, context) -> None, as ssl's sni_callback.
    Fails:   never; a client's name that cannot be recorded is ignored.
    Feeds:   build_tls."""
    def note(sock, name, _context):
        """Purpose: the callback itself.
        Inputs:  sock — the TLS socket; name — the SNI or None; _context — unused.
        Returns: None: the handshake goes on with the same certificate.
        Fails:   never.
        Feeds:   ssl, during a handshake."""
        if name:
            try:
                peer = sock.getpeername()[0]
            except OSError:
                peer = ""
            state.saw_name(name, peer)
    return note


def build_tls(pem_path, state):
    """Purpose: the site's TLS context. The certificate and key come from a file only this process can reach, read once
             here (manual 1.3.6.3).
    Inputs:  pem_path — str, certificate chain and key in one file; state — SiteState.
    Returns: ssl.SSLContext: TLS 1.2 or newer, no session tickets, so every connection shows the certificate.
    Fails:   ssl.SSLError / OSError on a bad file.
    Feeds:   listener/site_main."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_TICKET
    context.load_cert_chain(pem_path)
    context.sni_callback = _note_name(state)
    return context
