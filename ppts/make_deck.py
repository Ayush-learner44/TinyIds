"""Builds ppts/TinyIDS.pptx in the style of reference/MWC2025013.pptx (palette, fonts, title layout).
Run from anywhere:  python ppts/make_deck.py
"""
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
IMG = HERE.parent / "evaluation_matrices" / "images"
ASSETS = HERE / "assets"

TEAL, TEXT, SUB = RGBColor(0x1F, 0x4E, 0x5F), RGBColor(0x1A, 0x1A, 0x1A), RGBColor(0x3A, 0x3A, 0x3A)
PANEL, BORDER, MUTED = RGBColor(0xF3, 0xF4, 0xF5), RGBColor(0xC9, 0xCD, 0xCF), RGBColor(0x7A, 0x7A, 0x7A)
RED, GREEN = RGBColor(0xB9, 0x1C, 0x1C), RGBColor(0x15, 0x80, 0x3D)
FONT, FONT_B = "Segoe UI", "Segoe UI Semibold"

prs = Presentation()
prs.slide_width, prs.slide_height = Emu(12192000), Emu(6858000)
W = prs.slide_width
BLANK = prs.slide_layouts[6]
page = [0]


def text(slide, x, y, w, h, s, size=16, bold=False, color=TEXT, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.05)
    lines = s if isinstance(s, list) else [s]
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(6)
        r = p.add_run()
        r.text = line
        r.font.size, r.font.name = Pt(size), FONT_B if bold else FONT
        r.font.color.rgb = color
    return tb


def rect(slide, x, y, w, h, fill, line=None):
    r = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    r.fill.solid()
    r.fill.fore_color.rgb = fill
    if line is None:
        r.line.fill.background()
    else:
        r.line.color.rgb = line
        r.line.width = Pt(0.75)
    r.shadow.inherit = False
    return r


def new_slide(title, subtitle=None):
    s = prs.slides.add_slide(BLANK)
    page[0] += 1
    text(s, Inches(0.95), Inches(0.55), Inches(11.4), Inches(0.6), title, 28, True, TEXT, PP_ALIGN.CENTER)
    rect(s, Inches(3.47), Inches(1.22), Inches(6.4), Emu(45720), TEAL)
    if subtitle:
        text(s, Inches(0.95), Inches(1.4), Inches(11.4), Inches(0.4), subtitle, 15, False, SUB, PP_ALIGN.CENTER)
    text(s, Inches(11.68), Inches(6.92), Inches(0.7), Inches(0.3), f"{page[0]:02d}", 11, False, MUTED, PP_ALIGN.RIGHT)
    return s


def picture(slide, path, x, y, max_w, max_h):
    w, h = Image.open(path).size
    scale = min(max_w / w, max_h / h)
    pw, ph = int(w * scale), int(h * scale)
    return slide.shapes.add_picture(str(path), x + (max_w - pw) // 2, y + (max_h - ph) // 2, pw, ph)


def panel(slide, x, y, w, h, head, body, head_color=TEAL, body_size=13):
    rect(slide, x, y, w, h, PANEL)
    rect(slide, x, y, w, Emu(27432), head_color)
    text(slide, x + Inches(0.2), y + Inches(0.18), w - Inches(0.4), Inches(0.45), head, 18, True, head_color)
    text(slide, x + Inches(0.2), y + Inches(0.68), w - Inches(0.4), h - Inches(0.8), body, body_size, False, SUB)


def table(slide, x, y, w, rows, col_w, size=12, row_h=0.36):
    t = slide.shapes.add_table(len(rows), len(rows[0]), x, y, w, Inches(row_h * len(rows))).table
    for j, cw in enumerate(col_w):
        t.columns[j].width = Inches(cw)
    for i, row in enumerate(rows):
        t.rows[i].height = Inches(row_h)
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.fill.solid()
            c.fill.fore_color.rgb = TEAL if i == 0 else (PANEL if i % 2 else RGBColor(0xFF, 0xFF, 0xFF))
            c.margin_left = c.margin_right = Inches(0.08)
            c.margin_top = c.margin_bottom = Inches(0.03)
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            p = c.text_frame.paragraphs[0]
            p.text = str(val)
            f = p.runs[0].font
            f.size, f.name = Pt(size), FONT_B if i == 0 else FONT
            f.color.rgb = RGBColor(0xFF, 0xFF, 0xFF) if i == 0 else TEXT
    return t


# ------------------------------------------------------------------------------------------------ 1 title
s = prs.slides.add_slide(BLANK)
page[0] += 1
text(s, Inches(0.5), Inches(0.45), Inches(12.3), Inches(0.6), "Indian Institute of Information Technology, Allahabad",
     36, True, TEXT, PP_ALIGN.CENTER)
text(s, Inches(0.5), Inches(1.42), Inches(12.3), Inches(0.4), "Department of Information Technology", 24, False, SUB,
     PP_ALIGN.CENTER)
picture(s, ASSETS / "logo.png", Inches(5.5), Inches(1.95), Inches(2.33), Inches(2.33))
text(s, Inches(0.9), Inches(4.5), Inches(11.5), Inches(0.9),
     ["TinyIDS: Explainable Intrusion Detection on a Raspberry Pi IoT Gateway"], 28, True, TEAL, PP_ALIGN.CENTER)
rect(s, Inches(2.95), Inches(5.78), Inches(7.4), Emu(49972), TEAL)
text(s, Inches(0.9), Inches(6.0), Inches(11.5), Inches(0.4), "SUBMITTED BY:   Ayush Gupta (MWC2025013)", 20, False,
     TEXT, PP_ALIGN.CENTER)

# ------------------------------------------------------------------------------------------------ 2 goal
s = new_slide("Goal", "A small, explainable IDS that runs live on the IoT gateway, detects and blocks attacks")
for i, (head, body) in enumerate([
        ("974 KB", ["LightGBM model", "target < 1 MB"]),
        ("~1 ms", ["per decision on the Pi", "target < 5 ms"]),
        ("5–14 ms", ["SHAP top-3 reasons per alert", "target < 50 ms"]),
        ("77–78 MB", ["RAM of the whole detector", "target < 100 MB"])]):
    panel(s, Inches(0.95 + i * 2.9), Inches(2.1), Inches(2.65), Inches(1.75), head, body, body_size=14)
text(s, Inches(0.95), Inches(4.25), Inches(11.4), Inches(0.4), "WHAT IT DOES", 16, True, TEAL)
text(s, Inches(0.95), Inches(4.7), Inches(11.4), Inches(2.0), [
    "•  Every 10 packets from a sender → 14 numbers → one model: Benign, Flood or Recon",
    "•  Every alert comes with its top-3 reasons (TreeSHAP), shown live on a dashboard",
    "•  Rules cover what a model cannot see: DoS vs DDoS, spoofing, MQTT brute force",
    "•  Attackers are blocked by the Pi's firewall automatically, for a limited time"], 16, False, SUB)

# ------------------------------------------------------------------------------------------------ 3-5 HLD
s = new_slide("High-Level Design", "3 NodeMCU sensors · Raspberry Pi 4 gateway · laptop (dashboard, bot master, attacks)")
picture(s, ASSETS / "hld.png", Inches(0.6), Inches(1.9), Inches(12.1), Inches(4.9))

s = new_slide("MQTT Topics", "Solid = published to the broker · dashed = delivered to a subscriber · one colour per topic")
picture(s, ASSETS / "topics.png", Inches(0.9), Inches(1.9), Inches(11.5), Inches(4.95))

s = new_slide("Inside the Detector", "Every packet goes through the model path and the rules at the same time")
picture(s, ASSETS / "detector.png", Inches(1.6), Inches(1.85), Inches(10.1), Inches(5.0))

# ------------------------------------------------------------------------------------------------ 6 attacks
s = new_slide("Attacks Detected", "Live on the real Pi (17 Nov); confidence of the alert")
table(s, Inches(0.95), Inches(1.95), Inches(11.4), [
    ["Attack", "Detected by", "Alert (live)", "Action"],
    ["SYN / UDP / ICMP / ACK / PSH-ACK / RST-FIN flood", "Model", "DoS flood 0.96–1.00", "Block 30 s"],
    ["Bot DDoS (3 NodeMCUs, TCP / UDP)", "Model + FloodCounter", "DDoS flood (3 senders) 0.96–1.00", "Quarantine 120 s"],
    ["Port scan", "Model + PortScanRule", "Recon 0.99 / 1.00", "Block 30 s"],
    ["Version scan", "Model", "Recon 0.99", "Block 30 s"],
    ["OS scan", "Model", "named Flood 0.96 (still blocked)", "Block 30 s"],
    ["MQTT brute force", "BruteForceRule", "BruteForce 1.00", "Block 30 s"],
], [4.1, 2.3, 3.0, 2.0], size=13, row_h=0.5)
text(s, Inches(0.95), Inches(6.55), Inches(11.4), Inches(0.35),
     "Normal traffic of the 3 NodeMCUs: 0 false alarms in the final live run.", 14, True, GREEN, PP_ALIGN.CENTER)

# ------------------------------------------------------------------------------------------------ 7 mitigation
s = new_slide("Mitigation (IPS)", "The Pi's Linux firewall (iptables) drops the attacker's packets; every action expires")
for i, (head, body) in enumerate([
        ("Block", ["Sure attack (≥ 0.90 or a rule)", "from an outside machine", "→ drop all packets, 30 s"]),
        ("Quarantine", ["Sure attack from one of", "OUR NodeMCUs (compromised)", "→ drop all packets, 120 s"]),
        ("Rate-limit", ["Unsure attack (0.70–0.90)", "seen 2 windows in a row", "→ only > 20 packets/s dropped, 30 s"])]):
    panel(s, Inches(0.95 + i * 3.87), Inches(2.0), Inches(3.6), Inches(2.3), head, body, body_size=14)
text(s, Inches(0.95), Inches(4.65), Inches(11.4), Inches(0.4), "SAFETY", 16, True, TEAL)
text(s, Inches(0.95), Inches(5.1), Inches(11.4), Inches(1.6), [
    "•  Below P(attack) 0.70 a window counts as normal: no alert, no action",
    "•  The admin laptop's SSH and dashboard connection are never blocked",
    "•  SYN cookies are on at start; the dashboard can switch blocking off or release everything"], 16, False, SUB)

# ------------------------------------------------------------------------------------------------ dashboard screenshots
s = new_slide("Live Dashboard", "Sensors, traffic at the gateway, model time and SHAP time per alert, IPS controls")
picture(s, ASSETS / "dash_overview.png", Inches(0.8), Inches(1.9), Inches(11.7), Inches(4.85))
text(s, Inches(0.95), Inches(6.82), Inches(10), Inches(0.3), "Screenshot: demo run on the Docker testbed", 10, False,
     MUTED)

s = new_slide("Every Alert Explains Itself", "Alert table with the top-3 reasons · SHAP chart: feature = value in that window")
picture(s, ASSETS / "dash_alerts.png", Inches(0.8), Inches(1.9), Inches(11.7), Inches(4.85))
text(s, Inches(0.95), Inches(6.82), Inches(10), Inches(0.3), "Screenshot: bot DDoS on the Docker testbed", 10, False,
     MUTED)

# ------------------------------------------------------------------------------------------------ 8 data + features
s = new_slide("Data and Features", "CICIoT2023 + our own recordings · only features the Pi computes exactly like the dataset")
panel(s, Inches(0.95), Inches(2.0), Inches(5.4), Inches(4.5), "Training data", [
    "•  CICIoT2023: 7.85 M rows, 34 labels",
    "•  Kept 13 labels: Benign, 9 floods, 3 scans",
    "•  20% sample of those: 909,368 rows",
    "•  + 36,255 rows recorded on our testbed and in the lab",
    "•  Class weights: a Recon row counts 13×, Benign 5.7× a Flood row"], body_size=14)
panel(s, Inches(6.75), Inches(2.0), Inches(5.6), Inches(4.5), "The 14 features (per 10 packets)", [
    "Sizes:  Min, Max, AVG, Std, Tot size",
    "TCP flags:  SYN, ACK, PSH, RST, FIN shares",
    "Protocol:  Protocol Type, TCP, UDP, ICMP",
    "",
    "Dropped 32: computed differently live, shortcuts (IAT), or always 0 for our attacks"], body_size=14)

# ------------------------------------------------------------------------------------------------ 9 training
s = new_slide("Model and Training", "One LightGBM model, 3 classes: Benign · Flood · Recon")
table(s, Inches(1.6), Inches(2.0), Inches(10.1), [
    ["Setting", "Value", "Why"],
    ["Trees", "189 (early stopping, max 300)", "stop before it overfits"],
    ["Tree size", "15 leaves, 63 value bins", "small and fast on the Pi"],
    ["Class weights", "Benign 4.68 · Flood 0.83 · Recon 10.86", "96% of rows are floods"],
    ["Decision", "attack if 1 − P(Benign) ≥ 0.70", "fewer false alarms"],
    ["Size", "974 KB", "target < 1 MB"],
    ["Explanation", "TreeSHAP, top-3 features per alert", "every alert says why"],
], [2.4, 4.2, 3.5], size=14, row_h=0.55)

# ------------------------------------------------------------------------------------------------ 10-11 results
s = new_slide("Results: Dataset Test Rows", "973,829 rows of CICIoT2023 never used in training")
picture(s, IMG / "cm_dataset_test.png", Inches(0.8), Inches(1.95), Inches(6.2), Inches(4.85))
for i, (head, body, col) in enumerate([
        ("0.997", ["attack-or-not F1"], TEAL), ("99.4%", ["of attacks detected"], TEAL),
        ("0.97%", ["false alarms"], TEAL), ("29%", ["of scans caught (weak class)"], RED)]):
    panel(s, Inches(7.4 + (i % 2) * 2.5), Inches(2.1 + (i // 2) * 2.1), Inches(2.3), Inches(1.8), head, body, col, 14)

s = new_slide("Results: Our Own Traffic", "Last 15% of every recording (split by time, never seen in training)")
picture(s, IMG / "cm_our_rows.png", Inches(0.8), Inches(1.95), Inches(6.2), Inches(4.85))
for i, (head, body, col) in enumerate([
        ("564 / 564", ["NodeMCU windows correct", "0 false alarms"], GREEN), ("99.9%", ["floods caught"], TEAL),
        ("78%", ["scans caught"], TEAL), ("0.945", ["macro-F1"], TEAL)]):
    panel(s, Inches(7.4 + (i % 2) * 2.5), Inches(2.1 + (i // 2) * 2.1), Inches(2.3), Inches(1.8), head, body, col, 14)

# ------------------------------------------------------------------------------------------------ 12 shap + speed
s = new_slide("Explainability and Speed on the Pi", "Measured live on the Raspberry Pi 4")
picture(s, IMG / "feature_importance.png", Inches(0.7), Inches(1.95), Inches(6.0), Inches(4.85))
table(s, Inches(7.0), Inches(2.2), Inches(5.4), [
    ["Measure", "On the Pi", "Target"],
    ["Model size", "974 KB", "< 1 MB"],
    ["Time per decision", "0.7–1.4 ms", "< 5 ms"],
    ["SHAP top-3 per alert", "5–14 ms", "< 50 ms"],
    ["RAM (detector)", "77–78 MB", "< 100 MB"],
], [2.3, 1.6, 1.5], size=14, row_h=0.55)
text(s, Inches(7.0), Inches(5.2), Inches(5.4), Inches(1.4),
     ["Packet sizes and protocol decide most cases; the TCP flags name the flood type in each alert."], 14, False, SUB)

# ------------------------------------------------------------------------------------------------ 13 limits
s = new_slide("Limitations and Future Work")
panel(s, Inches(0.95), Inches(1.8), Inches(5.5), Inches(4.7), "Limitations", [
    "•  Scans are the weak class (29% on the dataset)",
    "•  The OS scan is caught but named “Flood”",
    "•  Fragmentation and low-rate DDoS not covered",
    "•  Energy per inference not measured (no USB meter)"], RED, 15)
panel(s, Inches(6.85), Inches(1.8), Inches(5.5), Inches(4.7), "Future work", [
    "•  Record more scans (incl. nmap -O) to train Recon",
    "•  Entropy rule for low-rate DDoS",
    "•  Run the RQ2 benchmark of all compressed models on the Pi",
    "•  More IoT devices and protocols"], TEAL, 15)

out = HERE / "TinyIDS.pptx"
prs.save(out)
print("saved", out, len(prs.slides), "slides")
