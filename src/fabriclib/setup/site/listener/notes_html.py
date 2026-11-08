from fabriclib.setup.site.listener.render_page import escape


def notes_html(lines):
    """Purpose: what setup printed before a question, as a page reads best: a line at the margin is a heading, an
             indented one an item, a deeper one a sub-item. The words are setup's own, so a refusal reads as on the
             terminal (manual 1.3.6.4).
    Inputs:  lines — list of str, without colour codes.
    Returns: str, HTML; "" with no lines.
    Fails:   never.
    Feeds:   listener/page_for."""
    out, in_list = [], False
    for line in lines:
        text = line.strip()
        if not text:
            continue
        depth = len(line) - len(line.lstrip())
        if depth == 0:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{escape(text)}</h3>")
            continue
        if not in_list:
            out.append("<ul class=notes>")
            in_list = True
        kind = ' class="sub"' if depth > 2 else ""
        out.append(f"<li{kind}>{escape(text)}</li>")
    if in_list:
        out.append("</ul>")
    return "".join(out)
