#!/usr/bin/env python3
"""Run inside the test browser image (decision 2.1.8.15): open each page in headless Chromium at a phone's width and
say what is wider than the screen. Driven over Chromium's DevTools pipe (file descriptors 3 and 4), so it needs no
port and no driver.

    python3 narrow_probe.py <width> <url> [<url> ...]     prints one JSON line per URL:
        {"url", "status", "width", "scroll_width", "wide": [up to 5 elements past the right edge], "error"}
"""
import json
import os
import subprocess
import sys

WIDE_JS = """(() => {
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
  return JSON.stringify({scroll: document.documentElement.scrollWidth, width: w, wide: out.slice(0, 5)});
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
    cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": 812, "deviceScaleFactor": 1,
                                                    "mobile": True}, session=s)
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
                       wide=got["wide"])
        except Exception as exc:          # one page's failure is reported, the rest still measured
            out["error"] = str(exc)
        print(json.dumps(out), flush=True)
    cdp.proc.kill()


if __name__ == "__main__":
    main()
