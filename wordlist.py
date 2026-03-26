# -*- coding: utf-8 -*-
"""
Burp Suite Extension: Wordlist Generator
=========================================
Four wordlists, each with its own Generate / Clear / Auto / Save buttons:
  1. Words        -- hostname tokens, path segments, param names
  2. Endpoints    -- full URL paths from the site map
  3. JS Endpoints -- paths/routes extracted from JS response bodies
  4. JS APIs      -- full http/wss API URLs found in JS response bodies

Features:
  - Generate All  -- runs all four lists at once
  - Clear All     -- resets all results and delta-tracking state
  - Per-tab Auto  -- watches the site map and processes only NEW items (delta mode)
  - Per-tab Clear -- clears just that tab without affecting others
  - In-scope only -- uses getSiteMap(prefix) so out-of-scope hosts are never loaded
  - Skip static   -- ignores css/img/font files (JS files are always scanned)

Filters: in-scope only | skip static files
"""

from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel, JButton, JTextArea, JScrollPane, JLabel,
    JFileChooser, JCheckBox, BoxLayout, JOptionPane,
    BorderFactory, JTabbedPane, SwingUtilities
)
from java.awt import BorderLayout, FlowLayout, Font, Color
from java.io import PrintWriter, OutputStreamWriter, FileOutputStream, BufferedWriter
import re
import threading
import time
import java.io
import java.net


# ===========================================================================
# Constants
# ===========================================================================

# Extensions that are always skipped when "Skip static" is on.
# 'js' is intentionally NOT in this set -- JS files are always parsed.
STATIC_EXTS = frozenset([
    'css', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg',
    'woff', 'woff2', 'ttf', 'eot', 'otf', 'map',
    'webp', 'bmp', 'tiff', 'pdf', 'zip', 'gz', 'tar',
    'mp4', 'mp3', 'avi', 'mov', 'swf',
])

# How often the Auto watcher polls for new site-map items (seconds)
AUTO_RUN_INTERVAL = 8

# Only read the first JS_SCAN_LIMIT bytes of a JS response body.
# Prevents excessive work on large minified bundles.
JS_SCAN_LIMIT = 512 * 1024  # 512 KB


# ===========================================================================
# JS mining patterns
# ===========================================================================

_EP_PATS = [
    r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]{2,200})['"`]''',
    r'''(?:path|url|endpoint|route|href|src|action)\s*[:=]\s*['"`]([/][^'"`\s]{1,200})['"`]''',
    r'''['"`](/(?:api|v\d|rest|graphql|ws|wss|internal|external|public|private|admin|auth|user|account)[^'"`\s]{0,200})['"`]''',
    r'''\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['"`]([/][^'"`\s]{1,200})['"`]''',
    r'''router\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([/][^'"`\s]{1,200})['"`]''',
    r'''['"`](/pages/[^'"`\s]{1,150})['"`]''',
]
_EP_RE = [re.compile(p, re.IGNORECASE) for p in _EP_PATS]

_API_PATS = [
    r'''(?:baseURL|baseUrl|base_url|apiUrl|apiURL|api_url|API_URL|endpoint|host|server|origin)\s*[:=]\s*['"`](https?://[^'"`\s]{4,300})['"`]''',
    r'''['"`](https?://[^'"`\s]{4,300}/(?:api|v\d|graphql|rest|gql|rpc|service|backend)[^'"`\s]{0,200})['"`]''',
    r'''process\.env\.([A-Z_]{3,60})\s*(?:\|\|)?\s*['"`](https?://[^'"`\s]{4,200})['"`]''',
    r'''['"`](wss?://[^'"`\s]{4,200})['"`]''',
]
_API_RE = [re.compile(p, re.IGNORECASE) for p in _API_PATS]


# ===========================================================================
# Utility functions
# ===========================================================================

def _safe(s, fallback=''):
    """Coerce any Java/Python string to a clean ASCII str. Never raises."""
    if s is None:
        return fallback
    try:
        if isinstance(s, bytes):
            s = s.decode('utf-8', 'replace')
        return unicode(s).encode('ascii', 'replace').decode('ascii')
    except Exception:
        try:
            return str(s).encode('ascii', 'replace').decode('ascii')
        except Exception:
            return fallback


def _clean(s):
    """Strip non-ASCII and control characters from a string. Never raises."""
    if not s:
        return ''
    try:
        if isinstance(s, bytes):
            s = s.decode('utf-8', 'replace')
        cleaned = unicode(s).encode('ascii', 'ignore').decode('ascii')
        return ''.join(c for c in cleaned if 31 < ord(c) < 127).strip()
    except Exception:
        return ''


def _get_ext(path):
    m = re.search(r'\.([a-zA-Z0-9]{1,6})(?:\?|$)', path or '')
    return m.group(1).lower() if m else ''


def _is_static(path):
    return _get_ext(path) in STATIC_EXTS


def _is_js_path(path):
    return _get_ext(path) == 'js'


def _is_js_content_type(resp_info):
    """Return True if the response Content-Type indicates JavaScript."""
    try:
        for hdr in resp_info.getHeaders():
            h = _safe(hdr).lower()
            if h.startswith('content-type:') and (
                    'javascript' in h or 'ecmascript' in h):
                return True
    except Exception:
        pass
    return False


def _parse_host(host):
    """Split host into (subdomain_labels, domain_root, tld)."""
    host = re.sub(r':\d+$', '', host or '').lower().strip()
    if not host:
        return [], '', ''
    parts = host.split('.')
    if len(parts) < 2:
        return [], host, ''
    return parts[:-2], parts[-2], parts[-1]


def _extract_path_words(path):
    words = set()
    for seg in re.split(r'[/\-_.]', path or ''):
        seg = seg.strip()
        if seg and len(seg) > 1 and not seg.isdigit():
            if not re.match(r'^[a-f0-9]{8,}$', seg, re.I):
                words.add(seg.lower())
    return words


def _extract_param_names(query):
    words = set()
    for pair in (query or '').split('&'):
        key = pair.split('=')[0].strip()
        if key and len(key) > 1:
            words.add(key.lower())
    return words


def _read_js_body(item, body_offset):
    """Read up to JS_SCAN_LIMIT bytes from a Burp response, return unicode str."""
    try:
        raw = item.getResponse()
        body_len = len(raw) - body_offset
        if body_len <= 0:
            return ''
        if body_len > JS_SCAN_LIMIT:
            chunk = raw[body_offset:body_offset + JS_SCAN_LIMIT]
        else:
            chunk = raw[body_offset:]
        try:
            return chunk.tostring().decode('utf-8', 'replace')
        except Exception:
            return str(chunk.tostring())
    except Exception:
        return ''


def _mine_endpoints(js):
    found = set()
    for pat in _EP_RE:
        for m in pat.finditer(js):
            try:
                ep = _clean(m.group(1).strip().rstrip('\'"`'))
            except Exception:
                continue
            if ep and len(ep) < 300 and '\n' not in ep and '\r' not in ep:
                if ep.startswith('/') or ep.startswith('http'):
                    found.add(ep)
    return found


def _mine_apis(js):
    found = set()
    for pat in _API_RE:
        for m in pat.finditer(js):
            try:
                val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
            except Exception:
                continue
            val = _clean(val.strip().rstrip('\'"`'))
            if val and len(val) < 400 and '\n' not in val:
                found.add(val)
    return found


# ===========================================================================
# WordlistPane -- one tab's scrollable output area
# ===========================================================================

class WordlistPane(JPanel):
    """
    Reusable pane containing:
      - Scrollable monospaced text area
      - Toolbar: Generate | Auto | Clear | Save... | Select All | entry count | status
    """

    def __init__(self, title, task_key, extender, stdout, stderr):
        super(WordlistPane, self).__init__(BorderLayout(4, 4))
        self._title    = title
        self._task_key = task_key
        self._ext      = extender
        self._stdout   = stdout
        self._stderr   = stderr
        self.setBorder(BorderFactory.createTitledBorder(title))

        # Text area
        self._txt = JTextArea()
        self._txt.setEditable(False)
        self._txt.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._txt.setLineWrap(False)

        # Labels
        self._lbl_count  = JLabel("0 entries")
        self._lbl_status = JLabel("")

        # Buttons
        btn_gen   = JButton("Generate")
        btn_clear = JButton("Clear")
        btn_save  = JButton("Save...")
        btn_sel   = JButton("Select All")

        btn_gen.addActionListener(self._on_gen)
        btn_clear.addActionListener(self._on_clear_pane)
        btn_save.addActionListener(self._on_save)
        btn_sel.addActionListener(lambda e: self._txt.selectAll())

        # Auto checkbox
        self._cb_auto = JCheckBox("Auto", False)
        self._cb_auto.setToolTipText(
            "Automatically process only NEW site-map items as you browse.")
        self._cb_auto.addItemListener(self._on_auto_toggle)

        # Toolbar
        bot = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        bot.add(btn_gen)
        bot.add(self._cb_auto)
        bot.add(btn_clear)
        bot.add(btn_save)
        bot.add(btn_sel)
        bot.add(self._lbl_count)
        bot.add(self._lbl_status)

        self.add(JScrollPane(self._txt), BorderLayout.CENTER)
        self.add(bot, BorderLayout.SOUTH)

        # Auto-run state
        self._auto_lock   = threading.Lock()
        self._auto_active = False

    # ---- event handlers -------------------------------------------------

    def _on_gen(self, event):
        self._ext._run_task(self._task_key, incremental=False)

    def _on_clear_pane(self, event):
        self.set_lines([])
        self._ext._clear_task(self._task_key)
        self._set_status("cleared")

    def _on_auto_toggle(self, event):
        if self._cb_auto.isSelected():
            self._start_auto()
        else:
            self._stop_auto()

    # ---- auto-run -------------------------------------------------------

    def _start_auto(self):
        with self._auto_lock:
            if self._auto_active:
                return
            self._auto_active = True
        t = threading.Thread(target=self._auto_loop)
        t.daemon = True
        t.start()
        self._set_status("watching...")

    def _stop_auto(self):
        with self._auto_lock:
            self._auto_active = False
        self._set_status("")

    def _auto_loop(self):
        while True:
            with self._auto_lock:
                if not self._auto_active:
                    break
            try:
                new_items = self._ext._get_new_items(self._task_key)
                if new_items:
                    self._set_status("+{} new...".format(len(new_items)))
                    self._ext._run_task(
                        self._task_key, incremental=True, items=new_items)
                    self._set_status("watching...")
            except Exception as e:
                self._stdout.println(
                    "[-] auto-loop [{}]: {}".format(self._task_key, str(e)))
            # Interruptible sleep
            for _ in range(AUTO_RUN_INTERVAL * 2):
                with self._auto_lock:
                    if not self._auto_active:
                        break
                time.sleep(0.5)

    # ---- data -----------------------------------------------------------

    def set_lines(self, lines):
        safe_lines = [_clean(l) for l in lines if _clean(l)]
        text = '\n'.join(safe_lines)
        n    = len(safe_lines)
        SwingUtilities.invokeLater(lambda: [
            self._txt.setText(text),
            self._lbl_count.setText("{:,} entries".format(n)),
        ])

    def get_text(self):
        return self._txt.getText().strip()

    def _set_status(self, msg):
        m = msg
        SwingUtilities.invokeLater(lambda: self._lbl_status.setText(m))

    # ---- save -----------------------------------------------------------

    def _on_save(self, event):
        text = self.get_text()
        if not text:
            JOptionPane.showMessageDialog(
                self, "Nothing to save -- generate first.",
                "Empty", JOptionPane.WARNING_MESSAGE)
            return
        chooser = JFileChooser()
        chooser.setDialogTitle("Save " + self._title)
        chooser.setSelectedFile(java.io.File(self._task_key + "_wordlist.txt"))
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            fos    = FileOutputStream(path)
            writer = BufferedWriter(OutputStreamWriter(fos, "UTF-8"))
            writer.write(text)
            writer.newLine()
            writer.close()
            self._stdout.println("[+] Saved: " + path)
            JOptionPane.showMessageDialog(
                self, "Saved to:\n" + path, "Saved",
                JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._stderr.println("[-] Save error: " + str(e))
            JOptionPane.showMessageDialog(
                self, "Error:\n" + str(e), "Error",
                JOptionPane.ERROR_MESSAGE)


# ===========================================================================
# BurpExtender
# ===========================================================================

class BurpExtender(IBurpExtender, ITab):

    # ---------------------------------------------------------------- init

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Wordlist Generator")

        # Per-task seen-URL sets (used by delta / auto-run tracking).
        # Each auto-run tab only processes URLs it has not seen before.
        self._seen_lock  = threading.Lock()
        self._seen_items = {
            'words':     set(),
            'endpoints': set(),
            'js_eps':    set(),
            'js_apis':   set(),
        }

        # Per-task accumulated results (auto-run appends; full scan resets).
        self._results_lock = threading.Lock()
        self._results = {
            'words':     set(),
            'endpoints': set(),
            'js_eps':    set(),
            'js_apis':   set(),
        }

        self._stdout.println("[*] Wordlist Generator loaded.")
        SwingUtilities.invokeLater(self._build_ui)

    # ---------------------------------------------------------------- ITab

    def getTabCaption(self):
        return "Wordlist Gen"

    def getUiComponent(self):
        return self._panel

    # ---------------------------------------------------------------- UI

    def _build_ui(self):
        self._panel = JPanel(BorderLayout(6, 6))
        self._panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # ---- Options strip ----------------------------------------------
        top = JPanel(FlowLayout(FlowLayout.LEFT, 14, 2))

        # Filters
        filt = JPanel()
        filt.setLayout(BoxLayout(filt, BoxLayout.Y_AXIS))
        filt.setBorder(BorderFactory.createTitledBorder("Filters"))
        self._cb_inscope     = JCheckBox("In-scope only",              True)
        self._cb_skip_static = JCheckBox("Skip static (css/img/font)", True)
        filt.add(self._cb_inscope)
        filt.add(self._cb_skip_static)

        # Words options
        wp = JPanel()
        wp.setLayout(BoxLayout(wp, BoxLayout.Y_AXIS))
        wp.setBorder(BorderFactory.createTitledBorder("Words"))
        self._cb_hostnames  = JCheckBox("Full hostnames",   True)
        self._cb_subdomains = JCheckBox("Subdomain labels", True)
        self._cb_roots      = JCheckBox("Domain roots",     True)
        self._cb_domains    = JCheckBox("Domain + TLD",     True)
        self._cb_paths      = JCheckBox("Path segments",    True)
        self._cb_params     = JCheckBox("Param names",      True)
        for cb in (self._cb_hostnames, self._cb_subdomains, self._cb_roots,
                   self._cb_domains, self._cb_paths, self._cb_params):
            wp.add(cb)

        # Endpoint options
        ep = JPanel()
        ep.setLayout(BoxLayout(ep, BoxLayout.Y_AXIS))
        ep.setBorder(BorderFactory.createTitledBorder("Endpoints"))
        self._cb_with_query  = JCheckBox("Include query string", False)
        self._cb_dedup       = JCheckBox("Dedup across hosts",   True)
        self._cb_strip_ext   = JCheckBox("Strip-ext variant",    True)
        self._cb_host_prefix = JCheckBox("Prefix with hostname", False)
        for cb in (self._cb_with_query, self._cb_dedup,
                   self._cb_strip_ext, self._cb_host_prefix):
            ep.add(cb)

        top.add(filt)
        top.add(wp)
        top.add(ep)

        # ---- Tabs -------------------------------------------------------
        self._pane_words   = WordlistPane(
            "Words",        "words",    self, self._stdout, self._stderr)
        self._pane_eps     = WordlistPane(
            "Endpoints",    "endpoints",self, self._stdout, self._stderr)
        self._pane_js_eps  = WordlistPane(
            "JS Endpoints", "js_eps",   self, self._stdout, self._stderr)
        self._pane_js_apis = WordlistPane(
            "JS APIs",      "js_apis",  self, self._stdout, self._stderr)

        tabs = JTabbedPane()
        tabs.addTab("Words",        self._pane_words)
        tabs.addTab("Endpoints",    self._pane_eps)
        tabs.addTab("JS Endpoints", self._pane_js_eps)
        tabs.addTab("JS APIs",      self._pane_js_apis)

        # ---- Bottom bar -------------------------------------------------
        self._lbl_status = JLabel("Ready.")
        self._lbl_status.setForeground(Color(0x00, 0x80, 0x00))

        btn_gen_all   = JButton("Generate All")
        btn_clear_all = JButton("Clear All")
        btn_gen_all.addActionListener(self._on_gen_all)
        btn_clear_all.addActionListener(self._on_clear_all)

        bot = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        bot.add(btn_gen_all)
        bot.add(btn_clear_all)
        bot.add(JLabel(" | "))
        bot.add(self._lbl_status)

        self._panel.add(top,  BorderLayout.NORTH)
        self._panel.add(tabs, BorderLayout.CENTER)
        self._panel.add(bot,  BorderLayout.SOUTH)

        self._callbacks.addSuiteTab(self)

    # ---------------------------------------------------------------- handlers

    def _on_gen_all(self, event):
        self._run_task('all', incremental=False)

    def _on_clear_all(self, event):
        for pane in (self._pane_words, self._pane_eps,
                     self._pane_js_eps, self._pane_js_apis):
            pane.set_lines([])
        with self._results_lock:
            for k in self._results:
                self._results[k] = set()
        with self._seen_lock:
            for k in self._seen_items:
                self._seen_items[k].clear()
        self._set_status("Cleared.", Color(0x80, 0x80, 0x80))

    # ---------------------------------------------------------------- task dispatcher

    def _run_task(self, key, incremental=False, items=None):
        """
        key         -- 'words' | 'endpoints' | 'js_eps' | 'js_apis' | 'all'
        incremental -- True  = process only the items list passed in; append results
                       False = full scan; reset results for this task first
        items       -- list of (uid, burp_item, java_url) when incremental=True
        """
        label = key + (" +delta" if incremental else "")
        self._set_status("Running: {} ...".format(label), Color(0x00, 0x80, 0xFF))
        t = threading.Thread(
            target=self._worker,
            kwargs={'key': key, 'incremental': incremental, 'items': items})
        t.daemon = True
        t.start()

    # ---------------------------------------------------------------- delta helper

    def _get_new_items(self, task_key):
        """
        Return (uid, item, url) tuples for site-map items not yet seen by task_key.
        Immediately marks the new items as seen so concurrent auto-loops
        for different tabs don't process the same URL twice.
        """
        inscope_only = self._cb_inscope.isSelected()
        all_items    = self._get_items(inscope_only)

        new = []
        with self._seen_lock:
            seen = self._seen_items[task_key]
            for item in all_items:
                try:
                    svc  = item.getHttpService()
                    req  = item.getRequest()
                    if not req:
                        continue
                    info = self._helpers.analyzeRequest(svc, req)
                    url  = info.getUrl()
                    uid  = _safe(url.toString())
                    if uid and uid not in seen:
                        new.append((uid, item, url))
                except Exception:
                    continue
            for uid, _, _ in new:
                seen.add(uid)
        return new

    # ---------------------------------------------------------------- site-map loader

    def _get_items(self, inscope_only):
        """
        Return the Burp site-map items to process.

        When inscope_only=True:
          Pass 1 -- getSiteMap(None), only read getHttpService() (cheap field read)
                    to discover unique hosts.
          Pass 2 -- call isInScope() once per unique host.
          Pass 3 -- call getSiteMap(prefix) for each in-scope host so Burp
                    never loads out-of-scope items into memory.

        When inscope_only=False:
          Return getSiteMap(None) directly.
        """
        if not inscope_only:
            return self._callbacks.getSiteMap(None) or []

        self._set_status("Finding in-scope hosts...", Color(0x00, 0x80, 0xFF))

        # Pass 1: collect unique (proto, host, port) cheaply
        all_items    = self._callbacks.getSiteMap(None) or []
        unique_hosts = {}
        for item in all_items:
            try:
                svc   = item.getHttpService()
                proto = _safe(svc.getProtocol(), 'http')
                host  = _safe(svc.getHost())
                port  = int(svc.getPort())
                hkey  = "{}://{}:{}".format(proto, host, port)
                if hkey not in unique_hosts:
                    unique_hosts[hkey] = (proto, host, port)
            except Exception:
                continue

        if not unique_hosts:
            return []

        # Pass 2: scope-check once per host
        in_scope_prefixes = []
        for hkey, (proto, host, port) in unique_hosts.items():
            try:
                is_default = (proto == 'https' and port == 443) or \
                             (proto == 'http'  and port == 80)
                if is_default:
                    base_url = "{}://{}/".format(proto, host)
                else:
                    base_url = "{}://{}:{}/".format(proto, host, port)
                if self._callbacks.isInScope(java.net.URL(base_url)):
                    in_scope_prefixes.append(base_url)
            except Exception:
                continue

        if not in_scope_prefixes:
            self._set_status(
                "No in-scope hosts found. Check Target > Scope.", error=True)
            return []

        self._stdout.println("[*] In-scope prefixes ({}): {}".format(
            len(in_scope_prefixes), ', '.join(in_scope_prefixes)))

        # Pass 3: fetch only in-scope items via getSiteMap(prefix)
        result   = []
        seen_ids = set()
        for prefix in in_scope_prefixes:
            for item in (self._callbacks.getSiteMap(prefix) or []):
                try:
                    uid = id(item)
                    if uid not in seen_ids:
                        seen_ids.add(uid)
                        result.append(item)
                except Exception:
                    result.append(item)
        return result

    # ---------------------------------------------------------------- worker

    def _worker(self, key, incremental=False, items=None):
        try:
            skip_static  = self._cb_skip_static.isSelected()
            with_query   = self._cb_with_query.isSelected()
            dedup        = self._cb_dedup.isSelected()
            strip_ext    = self._cb_strip_ext.isSelected()
            host_prefix  = self._cb_host_prefix.isSelected()

            run_words   = key in ('all', 'words')
            run_eps     = key in ('all', 'endpoints')
            run_js_eps  = key in ('all', 'js_eps')
            run_js_apis = key in ('all', 'js_apis')
            need_js     = run_js_eps or run_js_apis

            task_keys_running = [k for k, r in [
                ('words', run_words), ('endpoints', run_eps),
                ('js_eps', run_js_eps), ('js_apis', run_js_apis),
            ] if r]

            if incremental and items is not None:
                # items already contains only unseen (uid, burp_item, java_url).
                # Mark them as seen for every sub-task we are running.
                with self._seen_lock:
                    for tk in task_keys_running:
                        for uid, _, _ in items:
                            self._seen_items[tk].add(uid)
                raw_items = [(burp_item, url) for _, burp_item, url in items]
            else:
                # Full scan: reset seen sets and accumulated results for
                # every task being run, then fetch all relevant items.
                inscope_only = self._cb_inscope.isSelected()
                all_burp_items = self._get_items(inscope_only)
                if not all_burp_items:
                    if not inscope_only:
                        self._set_status("Site map is empty.", error=True)
                    return

                with self._seen_lock:
                    for tk in task_keys_running:
                        self._seen_items[tk].clear()
                with self._results_lock:
                    for tk in task_keys_running:
                        self._results[tk] = set()

                raw_items = []
                for item in all_burp_items:
                    try:
                        info = self._helpers.analyzeRequest(
                            item.getHttpService(), item.getRequest())
                        raw_items.append((item, info.getUrl()))
                    except Exception:
                        continue

            # ---- per-item processing ------------------------------------
            words     = set()
            endpoints = set()
            js_eps    = set()
            js_apis   = set()
            seen_hosts = set()
            total      = len(raw_items)

            for idx, (item, url) in enumerate(raw_items):
                if idx % 100 == 0:
                    pct  = int(idx * 100.0 / total) if total else 100
                    mode = "+delta" if incremental else "full"
                    self._set_status(
                        "[{}/{}] {}%  ({}/{})".format(key, mode, pct, idx, total),
                        Color(0x00, 0x80, 0xFF))

                request = item.getRequest()
                if not request:
                    continue

                host  = _safe(url.getHost())
                path  = _safe(url.getPath(), '/')
                query = _safe(url.getQuery())

                is_js     = _is_js_path(path)
                is_static = _is_static(path)

                # ---- JS body parsing ------------------------------------
                if need_js and (is_js or not is_static):
                    response = item.getResponse()
                    if response:
                        resp_info = self._helpers.analyzeResponse(response)
                        is_js_ct  = _is_js_content_type(resp_info)
                        if is_js or is_js_ct:
                            js_text = _read_js_body(item, resp_info.getBodyOffset())
                            if js_text:
                                if run_js_eps:
                                    js_eps.update(_mine_endpoints(js_text))
                                if run_js_apis:
                                    js_apis.update(_mine_apis(js_text))

                # ---- Skip static for words + endpoints ------------------
                if skip_static and (is_static or is_js):
                    # Still harvest host words even for static/JS URLs
                    if run_words and host and host not in seen_hosts:
                        seen_hosts.add(host)
                        self._add_host_words(words, host)
                    continue

                # ---- Words ----------------------------------------------
                if run_words:
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        self._add_host_words(words, host)
                    if self._cb_paths.isSelected():
                        words.update(_extract_path_words(path))
                    if self._cb_params.isSelected():
                        words.update(_extract_param_names(query))

                # ---- Endpoints ------------------------------------------
                if run_eps:
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)

                    def _add_ep(p, _h=host, _q=query):
                        qs   = ('?' + _q) if with_query and _q else ''
                        full = p + qs
                        key2 = (_h + full) if (host_prefix or not dedup) else full
                        endpoints.add(key2)

                    _add_ep(path)
                    if strip_ext:
                        no_ext = re.sub(r'\.[a-zA-Z0-9]{1,6}$', '', path)
                        if no_ext and no_ext != path:
                            _add_ep(no_ext)

            # ---- merge into accumulated results and update UI -----------
            words.discard('')
            endpoints.discard('')
            js_eps.discard('')
            js_apis.discard('')

            counts = []
            with self._results_lock:
                if run_words:
                    self._results['words'].update(words)
                    sw = sorted(self._results['words'])
                    self._pane_words.set_lines(sw)
                    counts.append("{:,} words".format(len(sw)))

                if run_eps:
                    self._results['endpoints'].update(endpoints)
                    se = sorted(self._results['endpoints'])
                    self._pane_eps.set_lines(se)
                    counts.append("{:,} endpoints".format(len(se)))

                if run_js_eps:
                    self._results['js_eps'].update(js_eps)
                    sje = sorted(self._results['js_eps'])
                    self._pane_js_eps.set_lines(sje)
                    counts.append("{:,} JS endpoints".format(len(sje)))

                if run_js_apis:
                    self._results['js_apis'].update(js_apis)
                    sja = sorted(self._results['js_apis'])
                    self._pane_js_apis.set_lines(sja)
                    counts.append("{:,} JS APIs".format(len(sja)))

            mode = "+delta" if incremental else "full"
            msg  = "[{}] Done -- {}  ({:,} hosts)".format(
                mode, " | ".join(counts) if counts else "nothing to do",
                len(seen_hosts))
            self._set_status(msg)
            self._stdout.println("[+] " + msg)

        except Exception as e:
            import traceback
            self._stderr.println("[-] Worker error: " + str(e))
            self._stderr.println(traceback.format_exc())
            self._set_status("Error: " + str(e), error=True)

    # ---------------------------------------------------------------- helpers

    def _clear_task(self, task_key):
        """Reset accumulated results and seen-URL set for a single task."""
        with self._results_lock:
            self._results[task_key] = set()
        with self._seen_lock:
            self._seen_items[task_key].clear()

    def _add_host_words(self, words, host):
        labels, root, tld = _parse_host(host)
        if self._cb_hostnames.isSelected():
            words.add(host)
        if self._cb_subdomains.isSelected():
            words.update(labels)
        if self._cb_roots.isSelected() and root:
            words.add(root)
        if self._cb_domains.isSelected() and root and tld:
            words.add(root + '.' + tld)

    def _set_status(self, msg, color=None, error=False):
        if color is None:
            color = Color(0xCC, 0x00, 0x00) if error else Color(0x00, 0x80, 0x00)
        c = color
        SwingUtilities.invokeLater(lambda: [
            self._lbl_status.setText(msg),
            self._lbl_status.setForeground(c),
        ])
