# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import (
    JPanel, JScrollPane, JTable, JButton, JLabel,
    JSplitPane, SwingUtilities, JFileChooser, BorderFactory
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Font, Color
import re
import csv
import threading


# ─────────────────────────────────────────────
#  Content types that can trigger XSS
# ─────────────────────────────────────────────
XSS_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/xml",
    "application/xml",
)


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Canary Tracker")
        callbacks.registerHttpListener(self)

        # canary -> { "source": (url, method, param), "reflections": set() }
        self.canary_map    = {}
        self.lock          = threading.Lock()
        self.canary_regex  = re.compile(r"(xss_[a-zA-Z0-9]+)")

        self._build_ui()
        callbacks.addSuiteTab(self)

    # ─────────────────────────────────────────
    #  UI
    # ─────────────────────────────────────────
    def _build_ui(self):

        # ── Seeds table ──────────────────────
        self.seed_cols  = ["Canary", "Method", "Seeded At (URL)", "Via Parameter"]
        self.seed_model = DefaultTableModel(self.seed_cols, 0)
        self.seed_table = JTable(self.seed_model)
        self.seed_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.seed_table.setSelectionBackground(Color(0xFF, 0xD7, 0x00))  # yellow highlight

        # ── Reflections table ─────────────────
        self.ref_cols  = ["Canary", "Reflected At (URL)", "Content-Type"]
        self.ref_model = DefaultTableModel(self.ref_cols, 0)
        self.ref_table = JTable(self.ref_model)
        self.ref_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.ref_table.setSelectionBackground(Color(0xFF, 0xD7, 0x00))

        # ── Clicking a seed filters reflections ──
        self.seed_table.getSelectionModel().addListSelectionListener(
            SeedSelectionListener(self)
        )

        # ── Section labels ────────────────────
        seed_label = JLabel("  Seeds  -  where your canary was inserted")
        seed_label.setFont(Font("SansSerif", Font.BOLD, 12))
        seed_label.setOpaque(True)
        seed_label.setBackground(Color(0x2B, 0x2B, 0x2B))
        seed_label.setForeground(Color.WHITE)

        ref_label = JLabel("  Reflections  -  every response that echoed the canary")
        ref_label.setFont(Font("SansSerif", Font.BOLD, 12))
        ref_label.setOpaque(True)
        ref_label.setBackground(Color(0x2B, 0x2B, 0x2B))
        ref_label.setForeground(Color(0xFF, 0xD7, 0x00))

        # ── Panels ────────────────────────────
        seed_panel = JPanel(BorderLayout())
        seed_panel.add(seed_label,                  BorderLayout.NORTH)
        seed_panel.add(JScrollPane(self.seed_table), BorderLayout.CENTER)

        ref_panel = JPanel(BorderLayout())
        ref_panel.add(ref_label,                   BorderLayout.NORTH)
        ref_panel.add(JScrollPane(self.ref_table),  BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, seed_panel, ref_panel)
        split.setDividerLocation(220)
        split.setResizeWeight(0.35)

        # ── Status bar ────────────────────────
        self.status_label = JLabel("  Ready - no canaries tracked yet")
        self.status_label.setFont(Font("SansSerif", Font.PLAIN, 11))

        clear_btn  = JButton("Clear All",  actionPerformed=self.clear_all)
        export_btn = JButton("Export CSV", actionPerformed=self.export_csv)
        show_all   = JButton("Show All Reflections", actionPerformed=self.show_all_reflections)

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_panel.add(clear_btn)
        btn_panel.add(export_btn)
        btn_panel.add(show_all)
        btn_panel.add(self.status_label)

        # ── Root panel ────────────────────────
        self.panel = JPanel(BorderLayout())
        self.panel.add(split,     BorderLayout.CENTER)
        self.panel.add(btn_panel, BorderLayout.SOUTH)

    # ─────────────────────────────────────────
    #  ITab
    # ─────────────────────────────────────────
    def getTabCaption(self):
        return "XSS Canary"

    def getUiComponent(self):
        return self.panel

    # ─────────────────────────────────────────
    #  IHttpListener
    # ─────────────────────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            url = self.helpers.analyzeRequest(messageInfo).getUrl()
            #if not self.callbacks.isInScope(url):
             #   return
            if messageIsRequest:
                self._handle_request(messageInfo)
            else:
                self._handle_response(messageInfo)
        except Exception as e:
            self.callbacks.printError("[XSS Canary] Dispatcher error: " + str(e))

    # ─────────────────────────────────────────
    #  Request - detect where canary was seeded
    # ─────────────────────────────────────────
    def _handle_request(self, messageInfo):
        try:
            request  = messageInfo.getRequest()
            analyzed = self.helpers.analyzeRequest(messageInfo)
            url      = analyzed.getUrl().toString()
            method   = analyzed.getMethod()

            # Parsed parameters (query string, body, cookies)
            for p in analyzed.getParameters():
                val = p.getValue()
                if val:
                    for canary in self.canary_regex.findall(val):
                        self._register_seed(canary, url, method, p.getName())

            # Raw body scan (catches JSON / XML / custom formats)
            offset = analyzed.getBodyOffset()
            if offset < len(request):
                body = self.helpers.bytesToString(request[offset:])
                for canary in self.canary_regex.findall(body):
                    self._register_seed(canary, url, method, "raw_body")

        except Exception as e:
            self.callbacks.printError("[XSS Canary] Request error: " + str(e))

    # ─────────────────────────────────────────
    #  Response - check ALL responses for canary
    # ─────────────────────────────────────────
    def _handle_response(self, messageInfo):
        try:
            # Cheap exit - nothing tracked yet
            with self.lock:
                if not self.canary_map:
                    return

            response = messageInfo.getResponse()
            if not response:
                return

            analyzed_resp = self.helpers.analyzeResponse(response)
            ct = self._xss_content_type(analyzed_resp.getHeaders())
            if not ct:
                return

            offset = analyzed_resp.getBodyOffset()
            if offset >= len(response):
                return

            body = self.helpers.bytesToString(response[offset:])
            if not body:
                return

            reflected_url = self.helpers.analyzeRequest(messageInfo).getUrl().toString()

            # Snapshot so we don't hold lock during body scan
            with self.lock:
                snapshot = list(self.canary_map.items())

            for canary, data in snapshot:
                if canary not in body:
                    continue

                with self.lock:
                    if reflected_url in data["reflections"]:
                        continue   # already logged this exact URL for this canary
                    data["reflections"].add(reflected_url)

                row = [canary, reflected_url, ct]

                def _add(r=row):
                    self.ref_model.addRow(r)
                    self._update_status()

                SwingUtilities.invokeLater(_add)

                # Highlight the response in Burp's history
                messageInfo.setHighlight("yellow")
                messageInfo.setComment("Canary reflected: " + canary)

        except Exception as e:
            self.callbacks.printError("[XSS Canary] Response error: " + str(e))

    # ─────────────────────────────────────────
    #  Register a new canary seed
    # ─────────────────────────────────────────
    def _register_seed(self, canary, url, method, param):
        with self.lock:
            if canary in self.canary_map:
                return   # already tracking this canary
            self.canary_map[canary] = {
                "source":      (url, method, param),
                "reflections": set()
            }

        row = [canary, method, url, param]

        def _add(r=row):
            self.seed_model.addRow(r)
            self._update_status()

        SwingUtilities.invokeLater(_add)

    # ─────────────────────────────────────────
    #  Content-type gate
    # ─────────────────────────────────────────
    def _xss_content_type(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                for allowed in XSS_CONTENT_TYPES:
                    if ct.startswith(allowed):
                        return ct    # return the actual content-type string
                return None          # wrong content-type
        return None                  # no content-type header

    # ─────────────────────────────────────────
    #  Status bar
    # ─────────────────────────────────────────
    def _update_status(self):
        with self.lock:
            n_canaries = len(self.canary_map)
        n_refs = self.ref_model.getRowCount()
        self.status_label.setText(
            "  Tracking {} canaries  |  {} reflection(s) found".format(n_canaries, n_refs)
        )

    # ─────────────────────────────────────────
    #  Filter reflections by selected seed
    # ─────────────────────────────────────────
    def filter_reflections_for(self, canary):
        self.ref_model.setRowCount(0)
        with self.lock:
            snapshot = list(self.canary_map.items())
        for c, data in snapshot:
            if c != canary:
                continue
            for ref_url in data["reflections"]:
                self.ref_model.addRow([c, ref_url, ""])

    # ─────────────────────────────────────────
    #  Button: Show All Reflections
    # ─────────────────────────────────────────
    def show_all_reflections(self, event=None):
        self.seed_table.clearSelection()
        self.ref_model.setRowCount(0)
        with self.lock:
            snapshot = list(self.canary_map.items())
        for canary, data in snapshot:
            for ref_url in data["reflections"]:
                self.ref_model.addRow([canary, ref_url, ""])

    # ─────────────────────────────────────────
    #  Button: Clear All
    # ─────────────────────────────────────────
    def clear_all(self, event):
        with self.lock:
            self.canary_map.clear()
        def _clear():
            self.seed_model.setRowCount(0)
            self.ref_model.setRowCount(0)
            self.status_label.setText("  Ready - no canaries tracked yet")
        SwingUtilities.invokeLater(_clear)

    # ─────────────────────────────────────────
    #  Button: Export CSV
    # ─────────────────────────────────────────
    def export_csv(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.endswith(".csv"):
            path += ".csv"
        try:
            with open(path, "w") as f:
                writer = csv.writer(f)

                writer.writerow(["=== SEEDS ==="])
                writer.writerow(self.seed_cols)
                for i in range(self.seed_model.getRowCount()):
                    writer.writerow(
                        [self.seed_model.getValueAt(i, j)
                         for j in range(self.seed_model.getColumnCount())]
                    )

                writer.writerow([])
                writer.writerow(["=== REFLECTIONS ==="])
                writer.writerow(self.ref_cols)
                for i in range(self.ref_model.getRowCount()):
                    writer.writerow(
                        [self.ref_model.getValueAt(i, j)
                         for j in range(self.ref_model.getColumnCount())]
                    )
        except Exception as e:
            self.callbacks.printError("[XSS Canary] Export error: " + str(e))


# ─────────────────────────────────────────────
#  Seed table row selection -> filter reflections
# ─────────────────────────────────────────────
class SeedSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.extender.seed_table.getSelectedRow()
        if row < 0:
            return
        canary = self.extender.seed_model.getValueAt(row, 0)
        self.extender.filter_reflections_for(canary)