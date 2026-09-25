#!/usr/bin/env python3
"""
soc_report.py — Génération d'un rapport d'activité SOC en PDF (pur Python)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Produit un PDF professionnel et sobre à partir de l'état du SOC
(soc_state.json) : résumé, activité par secteur, IP bloquées, machines
ciblées (brute force / scans), derniers événements de sécurité.

AUCUNE dépendance externe : mini-moteur PDF intégré (texte + tableaux +
pagination), police standard Helvetica (WinAnsi, accents FR gérés).

Usage : from soc_report import generate_report_pdf
        path = generate_report_pdf()   # -> chemin du PDF généré
"""

import os
from datetime import datetime

from soc_config import Config
from soc_utils import load_state

# ── Géométrie A4 (points PostScript : 1 pt = 1/72 pouce) ──
PAGE_W, PAGE_H = 595.0, 842.0
MARGIN = 42.0
CONTENT_W = PAGE_W - 2 * MARGIN


# ╔══════════════════════════════════════════════════════════╗
# ║              MINI-MOTEUR PDF (pur Python)                ║
# ╚══════════════════════════════════════════════════════════╝

def _esc(s: str) -> str:
    """Échappe le texte pour une chaîne PDF et le limite au latin-1."""
    s = (s or "").encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


# Largeurs approximatives des glyphes Helvetica (millièmes d'em) pour
# tronquer proprement le texte trop long. Valeur moyenne suffisante ici.
def _text_width(s: str, size: float) -> float:
    return len(s) * size * 0.52


def _fit(s: str, size: float, max_w: float) -> str:
    """Tronque une chaîne pour tenir dans max_w points (ajoute … si besoin)."""
    s = s or ""
    if _text_width(s, size) <= max_w:
        return s
    while s and _text_width(s + "...", size) > max_w:
        s = s[:-1]
    return s + "..."


class PDF:
    """Générateur PDF minimal : pages, texte, lignes, rectangles."""

    def __init__(self):
        self.pages = []      # chaque page = liste d'opérations (str)
        self._ops = None
        self.y = 0.0         # curseur vertical (origine EN HAUT de page)
        self.new_page()

    def new_page(self):
        self._ops = []
        self.pages.append(self._ops)
        self.y = MARGIN

    def _Y(self, y_top: float) -> float:
        """Convertit une coordonnée 'depuis le haut' en coordonnée PDF."""
        return PAGE_H - y_top

    def space(self, needed: float):
        """Saute de page si l'espace restant est insuffisant."""
        if self.y + needed > PAGE_H - MARGIN:
            self.new_page()

    def text(self, x, s, size=10, bold=False, gray=0.0, y=None):
        yy = self.y if y is None else y
        font = "F2" if bold else "F1"
        self._ops.append(
            f"q {gray:.3f} g BT /{font} {size:.1f} Tf "
            f"{x:.1f} {self._Y(yy):.1f} Td ({_esc(s)}) Tj ET Q"
        )

    def line(self, x1, y1, x2, y2, gray=0.0, w=0.6):
        self._ops.append(
            f"q {w:.2f} w {gray:.3f} G {x1:.1f} {self._Y(y1):.1f} m "
            f"{x2:.1f} {self._Y(y2):.1f} l S Q"
        )

    def rect(self, x, y_top, w, h, fill=None, stroke=None, lw=0.5):
        y = self._Y(y_top) - h
        seg = "q "
        if fill is not None:
            seg += f"{fill:.3f} g "
        if stroke is not None:
            seg += f"{stroke:.3f} w {stroke if False else 0:.3f} G "
        seg += f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re "
        seg += "f Q" if fill is not None else "S Q"
        self._ops.append(seg)

    # ── Éléments de haut niveau ────────────────────────────
    def heading(self, txt, size=12):
        self.space(size + 14)
        self.y += 6
        self.text(MARGIN, txt, size=size, bold=True, gray=0.12)
        self.y += 4
        self.line(MARGIN, self.y, PAGE_W - MARGIN, self.y, gray=0.6, w=0.6)
        self.y += 12

    def para(self, txt, size=10, gray=0.15, gap=13):
        self.space(gap)
        self.text(MARGIN, _fit(txt, size, CONTENT_W), size=size, gray=gray)
        self.y += gap

    def table(self, headers, rows, widths, size=9):
        """Dessine un tableau simple avec en-tête grisé et lignes fines."""
        rh = size + 6           # hauteur de ligne
        xs = [MARGIN]
        for w in widths:
            xs.append(xs[-1] + w * CONTENT_W)

        def draw_header():
            self.space(rh * 2)
            self.rect(MARGIN, self.y, CONTENT_W, rh, fill=0.90)
            for i, h in enumerate(headers):
                self.text(xs[i] + 3, h, size=size, bold=True, gray=0.1,
                          y=self.y + rh - 3)
            self.y += rh

        draw_header()
        for r in rows:
            if self.y + rh > PAGE_H - MARGIN:
                self.new_page()
                draw_header()
            for i, cell in enumerate(r):
                col_w = widths[i] * CONTENT_W - 6
                self.text(xs[i] + 3, _fit(str(cell), size, col_w),
                          size=size, gray=0.15, y=self.y + rh - 3)
            self.line(MARGIN, self.y + rh, PAGE_W - MARGIN, self.y + rh,
                      gray=0.85, w=0.4)
            self.y += rh
        self.y += 6

    # ── Assemblage / écriture du fichier ───────────────────
    def output(self, path):
        objs = []           # corps de chaque objet (bytes)

        def add(obj: bytes) -> int:
            objs.append(obj)
            return len(objs)   # numéro d'objet (1-based)

        font1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                    b"/Encoding /WinAnsiEncoding >>")
        font2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                    b"/Encoding /WinAnsiEncoding >>")

        # Numéro d'objet du noeud Pages (créé après, on réserve l'index)
        pages_obj_num = len(objs) + 1 + 2 * len(self.pages) + 1
        # Astuce : on construit d'abord les pages + contenus, puis Pages, puis Catalog.

        page_obj_nums = []
        content_specs = []
        for ops in self.pages:
            stream = ("\n".join(ops)).encode("latin-1", "replace")
            content_num = add(
                b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
            )
            page_num = add(b"")   # placeholder, rempli après (besoin de pages_obj_num)
            page_obj_nums.append((page_num, content_num))

        # Vrai numéro du noeud Pages maintenant
        pages_num = add(b"")   # placeholder

        # Remplir les pages (référencent pages_num + fonts + leur contenu)
        for (page_num, content_num) in page_obj_nums:
            objs[page_num - 1] = (
                b"<< /Type /Page /Parent %d 0 R "
                b"/MediaBox [0 0 %d %d] "
                b"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "
                b"/Contents %d 0 R >>"
                % (pages_num, int(PAGE_W), int(PAGE_H), font1, font2, content_num)
            )

        kids = " ".join(f"{n} 0 R" for (n, _) in page_obj_nums)
        objs[pages_num - 1] = (
            b"<< /Type /Pages /Count %d /Kids [ %s ] >>"
            % (len(page_obj_nums), kids.encode("latin-1"))
        )

        catalog_num = add(b"<< /Type /Catalog /Pages %d 0 R >>" % pages_num)

        # Écriture avec table xref
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (len(objs) + 1)
        for i, body in enumerate(objs, start=1):
            offsets[i] = len(out)
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"

        xref_pos = len(out)
        out += b"xref\n0 %d\n" % (len(objs) + 1)
        out += b"0000000000 65535 f \n"
        for i in range(1, len(objs) + 1):
            out += b"%010d 00000 n \n" % offsets[i]
        out += (b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF"
                % (len(objs) + 1, catalog_num, xref_pos))

        with open(path, "wb") as f:
            f.write(out)
        return path


# ╔══════════════════════════════════════════════════════════╗
# ║           CONSTRUCTION DU CONTENU DU RAPPORT             ║
# ╚══════════════════════════════════════════════════════════╝

SECTOR_LABELS = {"sante": "Sante (Hopital)", "banque": "Banque",
                 "energie": "Energie (CEET)", "inconnu": "Autre / inconnu"}


def _report_data(state: dict) -> dict:
    """Agrège les données de l'état pour le rapport."""
    blocked = state.get("blocked_ips", {})
    logs = state.get("logs", [])
    stats = state.get("stats", {})
    by_sector = stats.get("by_sector", {})
    cases = state.get("cases", [])
    pending = [d for d in state.get("pending_decisions", []) if d.get("status") == "pending"]

    # Machines ciblées : agrégées depuis les catégories des IP bloquées
    cat_counts = {}
    for info in blocked.values():
        c = info.get("category", "autre") or "autre"
        cat_counts[c] = cat_counts.get(c, 0) + 1

    return {
        "blocked": blocked,
        "logs": logs,
        "stats": stats,
        "by_sector": by_sector,
        "cases": cases,
        "pending": pending,
        "cat_counts": cat_counts,
    }


def generate_report_pdf(out_path: str = None) -> str:
    """Génère le rapport PDF et retourne son chemin."""
    if not out_path:
        out_dir = os.path.dirname(Config.STATE_FILE) or "."
        out_path = os.path.join(out_dir, "rapport_soc.pdf")

    state = load_state()
    d = _report_data(state)
    now = datetime.now().strftime("%d/%m/%Y a %H:%M:%S")

    pdf = PDF()

    # ── En-tête ──
    pdf.text(MARGIN, "RAPPORT D'ACTIVITE SOC", size=18, bold=True, gray=0.1)
    pdf.y += 20
    pdf.text(MARGIN, "ESIG Tech Arena - Securite des infrastructures critiques",
             size=10, gray=0.4)
    pdf.y += 14
    pdf.text(MARGIN, f"Genere le {now}", size=9, gray=0.4)
    if Config.THEHIVE_ORG:
        pdf.text(PAGE_W - MARGIN - 150, f"Organisation : {Config.THEHIVE_ORG}",
                 size=9, gray=0.4, y=pdf.y)
    pdf.y += 8
    pdf.line(MARGIN, pdf.y, PAGE_W - MARGIN, pdf.y, gray=0.3, w=1.0)
    pdf.y += 8

    # ── 1. Résumé ──
    st = d["stats"]
    pdf.heading("1. Resume")
    resume = [
        f"IP bloquees (total actuel) : {len(d['blocked'])}",
        f"Blocages aujourd'hui : {st.get('total_today', 0)}   |   cette semaine : {st.get('total_week', 0)}",
        f"Brute force detectes : {st.get('total_bruteforce', 0)}   |   Malware : {st.get('total_malware', 0)}   |   ICS/SCADA : {st.get('total_ics', 0)}",
        f"Cases TheHive (IP publiques) : {st.get('total_cases_public', 0)}",
        f"Decisions en attente de validation : {len(d['pending'])}",
    ]
    for line in resume:
        pdf.para(line)

    # ── 2. Activité par secteur ──
    pdf.heading("2. Activite par secteur d'infrastructure")
    if d["by_sector"]:
        rows = []
        for sec, v in sorted(d["by_sector"].items()):
            rows.append([
                SECTOR_LABELS.get(sec, sec),
                v.get("alerts", 0), v.get("blocked", 0),
                v.get("pending", 0), v.get("validations", 0),
            ])
        pdf.table(
            ["Secteur", "Alertes", "Bloques", "En attente", "Validations"],
            rows, widths=[0.40, 0.15, 0.15, 0.15, 0.15])
    else:
        pdf.para("Aucune activite enregistree par secteur.", gray=0.4)

    # ── 3. IP bloquées ──
    pdf.heading("3. IP bloquees")
    if d["blocked"]:
        rows = []
        for ip, info in list(d["blocked"].items())[:40]:
            statut = "Permanent" if info.get("permanent") else "Temporaire"
            rows.append([
                ip,
                info.get("category", "-") or "-",
                (info.get("raison", "") or "-")[:38],
                info.get("source", "-") or "-",
                statut,
            ])
        pdf.table(
            ["Adresse IP", "Categorie", "Raison", "Source", "Statut"],
            rows, widths=[0.20, 0.16, 0.36, 0.16, 0.12])
    else:
        pdf.para("Aucune IP actuellement bloquee.", gray=0.4)

    # ── 4. Menaces par catégorie ──
    pdf.heading("4. Menaces par categorie")
    if d["cat_counts"]:
        rows = [[k, v] for k, v in sorted(d["cat_counts"].items(),
                                          key=lambda kv: -kv[1])]
        pdf.table(["Categorie de menace", "Nombre d'IP bloquees"],
                  rows, widths=[0.6, 0.4])
    else:
        pdf.para("Aucune menace enregistree.", gray=0.4)

    # ── 5. Derniers événements de sécurité ──
    pdf.heading("5. Derniers evenements de securite")
    security_actions = {
        "BLOCAGE", "BLOQUE_PRIVE", "BLOCAGE_RECIDIVE", "CASE_CREE",
        "DETECTE_NATIF", "VALIDATION_REQUISE", "VALIDATION_APPROUVEE",
        "FAUX_POSITIF", "BAN_PERMANENT", "SELF_MONITORING",
    }
    evts = [l for l in d["logs"] if l.get("action") in security_actions][:25]
    if evts:
        rows = []
        for l in evts:
            rows.append([
                l.get("timestamp", "")[:19],
                l.get("action", ""),
                l.get("ip", "") or "-",
                (l.get("detail", "") or "")[:44],
            ])
        pdf.table(["Date/heure", "Action", "IP", "Detail"],
                  rows, widths=[0.22, 0.20, 0.16, 0.42])
    else:
        pdf.para("Aucun evenement de securite recent.", gray=0.4)

    # ── Pied de page sur chaque page ──
    total = len(pdf.pages)
    for i, ops in enumerate(pdf.pages, start=1):
        y = PAGE_H - (PAGE_H - MARGIN + 14)  # ~ bas de page
        ops.append(
            f"q 0.5 g BT /F1 8 Tf {MARGIN:.1f} {24:.1f} Td "
            f"(ESIG Tech Arena - SOC infrastructures critiques) Tj ET Q"
        )
        ops.append(
            f"q 0.5 g BT /F1 8 Tf {PAGE_W - MARGIN - 60:.1f} {24:.1f} Td "
            f"(Page {i}/{total}) Tj ET Q"
        )

    return pdf.output(out_path)


if __name__ == "__main__":
    p = generate_report_pdf("/tmp/rapport_soc_test.pdf")
    print("PDF genere :", p, os.path.getsize(p), "octets")
