"""Not a test: which of a console page's forms a person can send, for the suites that check greyed-out controls
(manual 1.8.6.15). A control a person lacks the permission for is shown greyed, not hidden, so a test asks whether a
form can be sent, not whether it is on the page."""
import html.parser


class _Live(html.parser.HTMLParser):
    """The post forms a person can send: a form counts when a button or submit in it is enabled and not inside a
    disabled fieldset."""
    def __init__(self):
        super().__init__()
        self.stack, self.form, self.live = [], None, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "fieldset":
            self.stack.append("disabled" in a)
        elif tag == "form" and (a.get("method") or "").lower() == "post":
            self.form = a.get("action", "")
        elif self.form is not None and (tag == "button" or (tag == "input" and a.get("type") == "submit")) \
                and "disabled" not in a and not any(self.stack) and a.get("type") != "button":
            self.live.append(self.form)

    def handle_endtag(self, tag):
        if tag == "fieldset" and self.stack:
            self.stack.pop()
        elif tag == "form":
            self.form = None


def live_forms(page):
    """The actions of the post forms in the page's <main> a person can send; greyed ones are left out."""
    parser = _Live()
    parser.feed(page.split("<main", 1)[-1].split("</main>", 1)[0])
    return sorted(set(parser.live))


def greyed(page, perm):
    """True when the page shows a control greyed for the permission."""
    return f"Needs the {perm} permission" in page
