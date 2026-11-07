// Optional: every page works without it (manual 1.3.6.5). The live log, reloading on a new phase, Copy, the finish's check.
(function () {
  "use strict";
  var body = document.body, log = document.getElementById("log");

  if (body.dataset.stream === "1" && window.EventSource) {
    var after = log ? log.dataset.logged : "0";
    var events = new EventSource("/events?after=" + encodeURIComponent(after));
    events.addEventListener("phase", function (e) {
      if (e.data !== body.dataset.version) { events.close(); window.location.reload(); }
    });
    if (log) {
      events.addEventListener("log", function (e) {
        var bottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
        log.appendChild(document.createTextNode("\n" + e.data));
        if (bottom) { log.scrollTop = log.scrollHeight; }
      });
      log.scrollTop = log.scrollHeight;
    }
  }

  document.querySelectorAll(".copy-button").forEach(function (button) {
    if (!navigator.clipboard) { return; }
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(button.parentElement.querySelector("code").textContent).then(function () {
        button.textContent = "Copied";
        window.setTimeout(function () { button.textContent = "Copy"; }, 1500);
      });
    });
  });

  var ua = navigator.userAgent, mine = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Ubuntu" : "";
  document.querySelectorAll("details").forEach(function (d) {
    if (d.querySelector("summary").textContent === mine) { d.open = true; }
  });

  function reach(url) {
    return window.fetch(url, { mode: "no-cors", cache: "no-store", credentials: "omit" })
      .then(function () { return true; }, function () { return false; });
  }

  var check = document.getElementById("check");
  if (check) {
    var button = document.getElementById("check-button"), out = document.getElementById("check-result");
    button.hidden = false;
    button.addEventListener("click", function () {
      var d = check.dataset;
      button.disabled = true;
      out.textContent = "Checking...";
      reach("https://" + d.name + ":" + d.port + "/check/" + d.nonce).then(function () {
        return reach("https://" + d.name + "/");
      }).then(function (console) {
        return window.fetch("/check-result/" + d.nonce + "?console=" + (console ? "1" : "0"));
      }).then(function (r) { return r.json(); }).then(function (v) {
        out.textContent = (v.ok ? "OK: " : "Not yet: ") + v.text;
      }, function () {
        out.textContent = "This page could not ask the site. Reload it and check again.";
      }).then(function () { button.disabled = false; });
    });
  }
}());
