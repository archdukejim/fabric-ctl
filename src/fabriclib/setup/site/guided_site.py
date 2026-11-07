import io
import queue
import signal
import sys
import threading
import time

from fabriclib.common.ask import use_front_end
from fabriclib.common.paths import LIB_DIR
from fabriclib.setup.detach.follow_run import follow_run
from fabriclib.setup.detect_network import detect_network
from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.certificate_fingerprint import certificate_fingerprint
from fabriclib.setup.site.check_console import check_console
from fabriclib.setup.site.close_site_port import close_site_port
from fabriclib.setup.site.constants import AFTER_SECONDS, FIRST_PORT, IDLE_SECONDS, LAST_PORT, PORT_RECORD
from fabriclib.setup.site.finish_data import finish_data
from fabriclib.setup.site.host_addresses import host_addresses
from fabriclib.setup.site.make_certificate import make_certificate
from fabriclib.setup.site.open_site_port import open_site_port
from fabriclib.setup.site.listener_link import ListenerLink
from fabriclib.setup.site.pick_port import pick_port
from fabriclib.setup.site.print_site_start import print_site_start
from fabriclib.setup.site.question_view import ANSI, question_view
from fabriclib.setup.site.read_port_record import read_port_record
from fabriclib.setup.site.read_site_files import read_site_files
from fabriclib.setup.site.restore_snapshot import restore_snapshot
from fabriclib.setup.site.session_keeper import SessionKeeper
from fabriclib.setup.site.take_snapshot import take_snapshot
from fabriclib.setup.site.tee_log import TeeLog
from fabriclib.setup.site.write_port_record import write_port_record

RESTART_GRACE, CLOSE_GRACE = 3.0, 1.5     # seconds for an open page to hear what comes next
LOG_REPLAY = 200_000                       # characters of the log a restarted listener starts with


class GuidedSite:
    """Guided on a new install, in the browser (manual 1.3.6): the terminal's questions and checks run here, as root,
    unchanged; this object is their front end, and owns the unprivileged listener, the code and the session."""

    def __init__(self, ctx, term=None, first=FIRST_PORT, last=LAST_PORT, idle=IDLE_SECONDS, after=AFTER_SECONDS,
                 record=PORT_RECORD, lib_dir=LIB_DIR, user="nobody", grace=RESTART_GRACE):
        """Purpose: hold what the site needs; nothing starts until open().
        Inputs:  ctx — SetupContext; term — the terminal's stream (default sys.stdout); first, last — the ports; idle,
                 after — the limits, seconds; record — the port's record; lib_dir, user — start_listener's; grace —
                 seconds an open page gets to hear of a restart. Tests give their own.
        Returns: None.
        Fails:   never.
        Feeds:   setup/run_setup."""
        self.ctx, self.term = ctx, term or sys.stdout
        self.first, self.last, self.idle, self.after, self.record = first, last, idle, after, record
        self.lib_dir, self.grace = lib_dir, grace
        self.answers = queue.Queue()
        self.done = threading.Event()   # Finish
        self.sock = None
        self.listener = ListenerLink(lib_dir, user)
        self.port, self.addresses, self.cert, self.key, self.fingerprint = None, [], "", "", ""
        self.keeper = SessionKeeper(self.say)
        self.seq = 0
        self.notes = io.StringIO()
        self.saved_stdout = None
        self.snapshot = None
        self.temporary, self.proceeded, self.closed, self.cancelled = True, False, False, False
        self.log_text = ""
        self.phase_now, self.finish = "question", {}
        self.host_check = lambda: "setup has not finished yet"

    def open(self):
        """Purpose: open the site: claim a port, ask about the firewall if it would block it (on the terminal: the one
                 question there), make the certificate and the code, start the listener, say it all on the terminal,
                 and from here every question goes to the browser and what setup prints goes on the page.
        Inputs:  none.
        Returns: self.
        Fails:   SetupError: every port taken, the firewall's question declined, the certificate or the listener
                 failing.
                 Whatever was made is taken back first: nothing changed.
        Feeds:   setup/run_setup."""
        other = read_port_record(self.record)
        if other:
            raise SetupError(f"another setup's site is running here on TCP {other['port']} (process {other['pid']}). "
                             "Finish or stop that one first. Nothing was changed.")
        self.snapshot = take_snapshot(self.ctx.target_dir)
        close_site_port(self.record)                     # what a killed run left, on its comment's evidence
        try:
            self.sock, self.port, found = pick_port(self.first, self.last)
            net = detect_network()
            self.addresses = host_addresses(net.get("host_ip"))
            opened = open_site_port(self.port, net.get("lan_cidr"))
            write_port_record(self.record, self.port, net.get("lan_cidr"))
            self.cert, self.key, self.fingerprint = make_certificate(self.addresses, net.get("hostname"))
            self._start()
        except BaseException:
            self.close()
            raise
        print_site_start(self.term, self.addresses or ["<this host's address>"], self.port, self.keeper.code,
                         self.fingerprint, found)
        if opened and net.get("lan_cidr"):
            self.say(f"  The firewall lets browsers in from {net['lan_cidr']} only: a URL on another network will not "
                     "open.\n\n")
        signal.signal(signal.SIGHUP, self._hang_up)
        signal.signal(signal.SIGTERM, self._hang_up)
        use_front_end(self)
        self.saved_stdout, sys.stdout = sys.stdout, self.notes
        return self

    def _hang_up(self, _number, _frame):
        """Purpose: the terminal went away, or the process was told to stop, before Proceed: as Ctrl-C, nothing changed.
                 After Proceed SIGTERM still ends this session's following, never the work.
        Inputs:  signal's arguments.
        Returns: never.
        Fails:   KeyboardInterrupt, always.
        Feeds:   signal, from open."""
        raise KeyboardInterrupt()

    @property
    def process(self):
        """Purpose: the listener's process, while there is one.
        Inputs:  none.
        Returns: Popen or None.
        Fails:   never.
        Feeds:   this class, tests."""
        return self.listener.process

    def _start(self):
        """Purpose: start a listener on the current certificate, telling it all it needs.
        Inputs:  none.
        Returns: None, once it says it is ready.
        Fails:   SetupError when it dies before that.
        Feeds:   open, _move_to_new_certificate."""
        cert, key = self.cert, self.key
        self.key = ""
        self.listener.start(self.sock, cert, key, {
            "t": "hello", "files": read_site_files(self.lib_dir), "port": self.port, "fingerprint": self.fingerprint,
            "temporary": self.temporary, "phase": self.phase_now, "token": self.keeper.token, "csrf": self.keeper.csrf,
            "log": self.log_text, "finish": self.finish}, self._on_message)

    def say(self, text):
        """Purpose: write to the terminal, which may have gone (a dropped SSH session after Proceed stops nothing).
        Inputs:  text — str.
        Returns: None.
        Fails:   never.
        Feeds:   this class, TeeLog."""
        try:
            self.term.write(text)
            self.term.flush()
        except (OSError, ValueError):
            pass

    def keep_log(self, text):
        """Purpose: one chunk of the run's log for the page, and for a restarted listener to start with.
        Inputs:  text — str.
        Returns: None.
        Fails:   never.
        Feeds:   TeeLog."""
        self.log_text = (self.log_text + text)[-LOG_REPLAY:]
        self.listener.send({"t": "log", "text": text})

    def _on_message(self, message):
        """Purpose: act on one thing the listener said, on its reading thread, so a code is judged while setup waits.
        Inputs:  message — dict.
        Returns: None.
        Fails:   never.
        Feeds:   _start."""
        kind = message.get("t")
        if kind == "code":
            self._judge_code(message)
        elif kind == "answer":
            if self.keeper.token:        # no answer before someone has given the code that only root's terminal shows
                self.keeper.noted("active")
                self.answers.put(message)
        elif kind == "cancel":
            if not self.proceeded:
                self.cancelled = True
                self.answers.put(message)
        elif kind == "finish":
            self.done.set()
        elif kind in ("active", "alive"):
            self.keeper.noted(kind)
        elif kind == "check":
            self.listener.send({"t": "reply", "id": message.get("id"), "problem": self.host_check()})

    def _judge_code(self, message):
        """Purpose: pass one try of the code to the keeper; a new session goes to the listener before the answer does.
        Inputs:  message — {"id", "code"}.
        Returns: None; the reply is sent.
        Fails:   never.
        Feeds:   _on_message."""
        reply = self.keeper.judge(message.get("code", ""))
        if reply["result"] == "ok":
            self.listener.send({"t": "session", "token": self.keeper.token, "csrf": self.keeper.csrf})
        self.listener.send({"t": "reply", "id": message.get("id"), **reply})

    def ask(self, qid, prompt, secret):
        """Purpose: common/ask's front end: put one question on the page, with what setup printed since the last, and
                 wait for the answer. The answer goes back to the same code that asked, which checks it as on the
                 terminal (manual 1.3.6.4). The plan's Menu is Advanced's and stays in the terminal: refused here.
        Inputs:  qid, prompt, secret — as ask() gets them.
        Returns: the answer as typed (str).
        Fails:   SetupError when the site was idle past the limit or its listener ended; SystemExit("setup cancelled")
                 on Cancel; KeyboardInterrupt from Ctrl-C. run_setup's close() then leaves nothing changed.
        Feeds:   common/ask."""
        while True:
            notes = ANSI.sub("", self.notes.getvalue()).splitlines()
            self.notes.seek(0)
            self.notes.truncate()
            self.seq += 1
            self.listener.send({"t": "question", "seq": self.seq, "notes": notes, **question_view(qid, prompt, secret)})
            value = self._wait_answer()
            if qid == "setup.plan" and value.strip().lower() not in ("p", "q"):
                self.notes.write(f"  {value!r}: Proceed or Cancel here; the menu stays in the terminal (setup, then "
                                 "Advanced)\n")
                self.notes.write("".join(line + "\n" for line in notes))
                continue
            return value

    def _wait_answer(self):
        """Purpose: wait for the current question's answer, keeping to the idle limit.
        Inputs:  none.
        Returns: the value (str).
        Fails:   as ask.
        Feeds:   ask."""
        while True:
            try:
                message = self.answers.get(timeout=0.5)
            except queue.Empty:
                if time.monotonic() - self.keeper.active > self.idle:
                    raise SetupError(f"the setup site was idle for {round(self.idle / 60)} minutes and has closed, "
                                     "with nothing changed. Start again: sudo fabricctl setup") from None
                if self.process.poll() is not None:
                    raise SetupError("the setup site's process ended, so setup stopped, with nothing changed. Start "
                                     "again: sudo fabricctl setup, or in this terminal: sudo fabricctl setup "
                                     "--terminal") from None
                continue
            if self.cancelled:
                raise SystemExit("setup cancelled")
            if str(message.get("seq")) == str(self.seq):
                return str(message.get("value", ""))

    def proceeding(self):
        """Purpose: Proceed was chosen: from here the work goes on whatever happens to the browser or the terminal
                 (2.1.2.26, manual 1.3.6.5). Questions and printing go back to the terminal; the page shows progress.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   setup/run_setup."""
        self.proceeded = True
        use_front_end(None)
        if self.saved_stdout:
            sys.stdout, self.saved_stdout = self.saved_stdout, None
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self._phase("running")
        self.say("\n  Proceed chosen in the browser. If the page is cut off, progress goes on here, and setup's last "
                 "words here\n  give the finish's steps (trust, DNS). After a lost session: sudo fabricctl setup "
                 "follows the run again.\n\n")

    def _phase(self, phase, **extra):
        """Purpose: move the page to another phase.
        Inputs:  phase — str; extra — what goes with it.
        Returns: None.
        Fails:   never.
        Feeds:   this class."""
        self.phase_now = phase
        self.listener.send({"t": "phase", "phase": phase, **extra})

    def follow(self, config_dir):
        """Purpose: hand_over's follower: show the run on the terminal and the page; its end decided by follow_run, with
                 its re-check (2.3.1.46). Then the finish or the failed step on the page, until Finish, the time limit
                 or Ctrl-C.
        Inputs:  config_dir — the install's config folder.
        Returns: the run's exit status (follow_run's); 130 after Ctrl-C while it ran: the work goes on, the site stops.
        Fails:   never for a failure of the finish's certificate: the page says so, on the temporary one.
        Feeds:   detach/hand_over, as its follow."""
        result = follow_run(config_dir, out=TeeLog(self))
        if result == 130:
            self._close_page("The terminal stopped following (Ctrl-C). Setup's work goes on; follow it there: "
                             "sudo fabricctl setup")
            return result
        if result:
            self._phase("failed", why=f"A step failed (exit status {result}). Its message is in the log below. Nothing "
                                      "more runs by itself: sudo fabricctl setup resumes from that step.")
            self.say("  The page shows the failure. Ctrl-C here closes the site.\n")
        else:
            self._finish_stage()
        self._wait_for_finish()
        return result

    def _finish_stage(self):
        """Purpose: setup ended well: the site moves to a certificate from fabric's new CA and shows the finish (manual
                 1.3.6.6). If that certificate cannot be had, the finish still shows, on the temporary one, saying so.
        Inputs:  none (the install's state).
        Returns: None.
        Fails:   never for the certificate.
        Feeds:   follow."""
        self.ctx.load_state()
        try:
            self.finish, chain, key = finish_data(self.ctx, self.addresses)
        except OSError as e:
            self._site_lost(str(e))
            return
        self.host_check = lambda: check_console(self.ctx)
        self.say(f"\n  fabric's root certificate, SHA-256: {self.finish['root_fingerprint']}\n")
        if chain:
            try:
                self._move_to_new_certificate(chain, key)
            except SetupError as e:
                self._site_lost(str(e).split(". Run Guided")[0])
                return
        else:
            self._phase("finish", finish=self.finish)
        self.say("  The page shows the finish: trust, DNS, the check, the console. Ctrl-C here, Finish there, or an "
                 "hour stops the site.\n")

    def _site_lost(self, why):
        """Purpose: the install is good but the site cannot show its finish: that must not read as a failed setup.
        Inputs:  why — str.
        Returns: None; the site is done.
        Fails:   never.
        Feeds:   _finish_stage."""
        self.listener.stop()
        self.done.set()
        self.say(f"\n  fabric is installed, but the setup site cannot show its finish: {why}.\n  Its steps, trust and "
                 "DNS, are in the manual, 4.3.6.2 and 4.3.6.3.\n")

    def _move_to_new_certificate(self, chain, key):
        """Purpose: restart the listener on the new certificate, on the same port, with the same session; the page first
                 hears what its browser will show.
        Inputs:  chain — str, leaf and intermediate; key — str.
        Returns: None.
        Fails:   SetupError when the listener will not start again.
        Feeds:   _finish_stage."""
        new = certificate_fingerprint(chain)
        self.say(f"  The site's new certificate, SHA-256: {new}\n")
        self._phase("restarting", why=new)
        time.sleep(self.grace)
        self.listener.stop()
        self.cert, self.key, self.fingerprint, self.temporary = chain, key, new, False
        self.phase_now = "finish"
        self._start()

    def _wait_for_finish(self):
        """Purpose: keep the site until Finish, the limit after setup's end, or Ctrl-C.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   follow."""
        try:
            self.done.wait(self.after)
        except KeyboardInterrupt:
            pass

    def _close_page(self, why):
        """Purpose: tell an open page why the site is going, and give it a moment.
        Inputs:  why — str.
        Returns: None.
        Fails:   never.
        Feeds:   follow, close.
        """
        if self.listener.link:
            self._phase("closed", why=why)
            time.sleep(min(CLOSE_GRACE, self.grace))

    def close(self, why=""):
        """Purpose: stop the site, in every case (manual 1.3.6.2, 1.3.6.8): the listener ended, the port closed, any
                 rule it opened removed, the key forgotten; and before Proceed, the install folder left as it was found.
                 Interrupts wait until this is done.
        Inputs:  why — what an open page is told.
        Returns: None.
        Fails:   never for a listener or a rule that has gone already; OSError restoring a file.
        Feeds:   setup/run_setup, open."""
        if self.closed:
            return
        self.closed = True
        # a second Ctrl-C here must not leave the port, the rule or the folder half-way
        for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            signal.signal(number, signal.SIG_IGN)
        use_front_end(None)
        if self.saved_stdout:
            sys.stdout, self.saved_stdout = self.saved_stdout, None
        if self.listener.link and self.phase_now != "closed":
            self._close_page(why or ("This temporary site has stopped; any port it opened is closed." if self.proceeded
                                     else "Setup was closed. Nothing was changed."))
        self.listener.stop()
        if self.sock:
            self.sock.close()
        self.key = self.cert = ""
        self.keeper.forget()
        removed = close_site_port(self.record)
        if not self.proceeded and self.snapshot is not None:
            restore_snapshot(self.ctx.target_dir, self.snapshot)
        if self.port:
            self.say(f"\n  The setup site has stopped: TCP {self.port} is closed"
                     + (", and the firewall rule opened for it removed.\n" if removed else ".\n"))
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)


