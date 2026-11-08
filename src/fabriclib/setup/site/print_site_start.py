def print_site_start(out, addresses, port, code, fingerprint, found):
    """Purpose: what the terminal says when the site opens (manual 1.3.6.2): each URL, the code, the fingerprint, what
             the temporary certificate means, how to leave. The code is printed nowhere else.
    Inputs:  out — the terminal's stream; addresses — list of str; port — int; code — str; fingerprint — str; found —
             what took the ports passed over (list of str).
    Returns: None.
    Fails:   OSError from a closed terminal.
    Feeds:   setup/site/guided_site."""
    lines = [f"  {note}: using {port}" for note in found]
    lines += ["", "  Guided setup goes on in your browser, on a temporary site:"]
    lines += [f"      https://{address}:{port}/" for address in addresses]
    lines += ["", f"  One-time code:  {code}", f"  Temporary certificate's SHA-256 fingerprint:\n      {fingerprint}",
              "",
              "  Your browser will warn about the certificate. Compare the fingerprint it shows with the one above, "
              "then",
              "  continue and enter the code. If you skip that check, someone on your LAN could intercept the page.",
              "  A temporary certificate is in use for as long as the site runs.", "",
              "  Ctrl-C, or 30 idle minutes, closes the site with nothing changed.",
              "  No browser to hand? Ctrl-C, then: sudo fabricctl setup --terminal", ""]
    out.write("\n".join(lines) + "\n")
    out.flush()
