#!/usr/bin/env python3
"""Run inside the test browser image (decision 2.1.8.15): open each page in headless Chromium at a phone's width (or
a desktop's) and say what is wider than the screen, with the top bar's menus open, and what the layout audit of
2.3.8.4.3 looks for (1.8.8.6): anything but a field in a field grid, a form's button in a grid cell of its own (not a
row the full width), boxes overlapping. Driven over Chromium's DevTools pipe (file descriptors 3 and 4), so it needs
no port and no driver.

    python3 narrow_probe.py <width> <url> [<url> ...]     prints one JSON line per URL:
        {"url", "status", "width", "scroll_width", "wide": [up to 5 elements past the right edge],
         "strays": [...], "lone": [...], "overlaps": [...], "error"}       (each list: up to 5)
"""
import json
import os
import subprocess
import sys

WIDE_JS = """(() => {
  // the top bar's menus opened first (the site selector, the person's menu: 1.8.6.12), so they are measured too
  document.querySelectorAll('.topbar details').forEach(d => { d.open = true; });
  const w = window.innerWidth, out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width && r.right > w + 1 && getComputedStyle(el).position !== 'fixed') {
      let inner = false;                      // inside a box that scrolls on its own: not the page
      for (let p = el.parentElement; p; p = p.parentElement) {
        const o = getComputedStyle(p).overflowX;
        if ((o === 'auto' || o === 'scroll' || o === 'hidden') && p.getBoundingClientRect().right <= w + 1) {
          inner = true; break;
        }
      }
      out.push((inner ? 'inner ' : '') + el.tagName.toLowerCase() + (el.className ? '.' + el.className : '') +
               ' right=' + Math.round(r.right));
    }
  }
  const name = el => el.tagName.toLowerCase() + (el.className && typeof el.className === 'string'
                                                   ? '.' + el.className.trim().split(/\\s+/).join('.') : '');
  const shown = el => { const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.position !== 'absolute' && cs.position !== 'fixed'
           && cs.visibility !== 'hidden'; };
  const strays = [], lone = [], overlaps = [];
  // a field grid holds fields only: no heading, paragraph, list or table among its cells
  for (const g of document.querySelectorAll('main .grid')) {
    const gr = g.getBoundingClientRect();
    for (const c of g.children) {
      if (!shown(c)) continue;
      if (/^(H[1-6]|P|TABLE|UL|OL|PRE)$/.test(c.tagName)) strays.push(name(g) + ' > ' + name(c));
      // a form's buttons are a row of their own, the full width: never one cell among the fields
      const btn = c.matches('button,.btn') || (c.tagName === 'DIV' && c.querySelector(':scope > button, :scope > .btn'));
      if (btn && gr.width - c.getBoundingClientRect().width > 2 && getComputedStyle(c).gridColumnEnd !== '-1')
        lone.push(name(g) + ' > ' + name(c));
    }
  }
  // no two boxes side by side or stacked overlap: the children of a card, a grid, a stack or the page's main
  for (const p of document.querySelectorAll('main, main .card, main .grid, main .stack, main .tiles')) {
    const kids = [...p.children].filter(shown);
    for (let i = 0; i < kids.length; i++) for (let j = i + 1; j < kids.length; j++) {
      const a = kids[i].getBoundingClientRect(), b = kids[j].getBoundingClientRect();
      const x = Math.min(a.right, b.right) - Math.max(a.left, b.left), y = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (x > 2 && y > 2) overlaps.push(name(p) + ': ' + name(kids[i]) + ' / ' + name(kids[j]));
    }
  }
  return JSON.stringify({scroll: document.documentElement.scrollWidth, width: w, wide: out.slice(0, 5),
                         strays: strays.slice(0, 5), lone: lone.slice(0, 5), overlaps: overlaps.slice(0, 5)});
})()"""


class Pipe:
    """The DevTools pipe: JSON messages, each ended by a NUL byte."""

    def __init__(self):
        r_in, w_in = os.pipe()          # we write, Chromium reads fd 3
        r_out, w_out = os.pipe()        # Chromium writes fd 4, we read
        self.proc = subprocess.Popen(
            ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--remote-debugging-pipe",
             "--no-first-run", "--disable-extensions", "about:blank"],
            pass_fds=(3, 4), preexec_fn=lambda: (os.dup2(r_in, 3), os.dup2(w_out, 4)),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(r_in)
        os.close(w_out)
        self.w, self.r = os.fdopen(w_in, "wb"), os.fdopen(r_out, "rb")
        self.n, self.buf, self.events = 0, b"", []

    def send(self, method, params=None, session=None):
        self.n += 1
        msg = {"id": self.n, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.w.write(json.dumps(msg).encode() + b"\0")
        self.w.flush()
        want = self.n
        while True:
            m = self.read()
            if m.get("id") == want:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})
            self.events.append(m)

    def read(self):
        while b"\0" not in self.buf:
            chunk = self.r.read1(65536)
            if not chunk:
                raise RuntimeError("Chromium closed the pipe")
            self.buf += chunk
        raw, self.buf = self.buf.split(b"\0", 1)
        return json.loads(raw)

    def wait_event(self, method, session):
        for i, m in enumerate(self.events):
            if m.get("method") == method and m.get("sessionId") == session:
                return self.events.pop(i)
        while True:
            m = self.read()
            if m.get("method") == method and m.get("sessionId") == session:
                return m
            self.events.append(m)


def main():
    width, urls = int(sys.argv[1]), sys.argv[2:]
    cdp = Pipe()
    target = cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
    s = cdp.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
    cdp.send("Page.enable", session=s)
    cdp.send("Network.enable", session=s)
    cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": 812 if width < 768 else 900,
                                                    "deviceScaleFactor": 1, "mobile": width < 768}, session=s)
    for url in urls:
        out = {"url": url}
        try:
            cdp.events.clear()
            cdp.send("Page.navigate", {"url": url}, session=s)
            cdp.wait_event("Page.loadEventFired", s)
            status = [m["params"]["response"]["status"] for m in cdp.events
                      if m.get("method") == "Network.responseReceived" and m.get("sessionId") == s
                      and m["params"].get("type") == "Document"]
            res = cdp.send("Runtime.evaluate", {"expression": WIDE_JS, "returnByValue": True}, session=s)
            got = json.loads(res["result"]["value"])
            out.update(status=status[-1] if status else None, width=got["width"], scroll_width=got["scroll"],
                       wide=got["wide"], strays=got["strays"], lone=got["lone"], overlaps=got["overlaps"])
        except Exception as exc:          # one page's failure is reported, the rest still measured
            out["error"] = str(exc)
        print(json.dumps(out), flush=True)
    cdp.proc.kill()


if __name__ == "__main__":
    main()
