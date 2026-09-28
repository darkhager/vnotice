"""One-off: render ONBOARDING.md's steps as a PDF for handing to a new
teammate. Not part of the app -- run manually when ONBOARDING.md changes."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
)
from reportlab.lib.enums import TA_LEFT

OUT = "ONBOARDING.pdf"

styles = getSampleStyleSheet()
title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=22, spaceAfter=4)
subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], textColor=colors.HexColor("#666666"), spaceAfter=20)
h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a1a"))
body = ParagraphStyle("BodyX", parent=styles["Normal"], fontSize=10.5, leading=15, spaceAfter=6, alignment=TA_LEFT)
note = ParagraphStyle("Note", parent=body, textColor=colors.HexColor("#8a5a00"), backColor=colors.HexColor("#fff6e0"),
                      borderPadding=8, spaceBefore=4, spaceAfter=10)
code_style = ParagraphStyle("Code", fontName="Courier", fontSize=8.7, leading=12,
                            textColor=colors.HexColor("#e8e8e8"))

def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def code_block(text: str):
    """A dark, monospace box for shell/code snippets."""
    lines = _escape(text.strip("\n")).split("\n")
    para = Paragraph("<br/>".join(l.replace(" ", "&nbsp;") or "&nbsp;" for l in lines), code_style)
    t = Table([[para]], colWidths=[6.3 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1e1e1e")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t

doc = SimpleDocTemplate(OUT, pagesize=letter,
                        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
                        leftMargin=0.9 * inch, rightMargin=0.9 * inch)
story = []

story.append(Paragraph("Onboarding &mdash; Vnotice", title_style))
story.append(Paragraph("Six steps to get set up and ship your first change.", subtitle_style))

# ── 1. Get access ──
story.append(Paragraph("1. Get access", h2))
story.append(ListFlowable([
    ListItem(Paragraph('Clone the repo: <font face="Courier">git clone https://github.com/darkhager/vnotice.git</font>', body)),
    ListItem(Paragraph("Ask the team for the SSH login to the production server "
                       '(<font face="Courier">vnotice@10.4.150.57</font>). '
                       "Never put that password in a file &mdash; keep it in your own password manager.", body)),
    ListItem(Paragraph('On Windows, install <b>PuTTY</b> &mdash; deployment uses its plink/pscp tools '
                       "(see step 5), not OpenSSH.", body)),
], bulletType="bullet", start="circle"))

# ── 2. Run it locally ──
story.append(Paragraph("2. Run it locally", h2))
story.append(Paragraph("Backend (SQLite, no Docker needed):", body))
story.append(code_block("""cd backend
.\\setup_local.ps1        # creates venv, installs deps, writes .env, starts uvicorn
# API:     http://localhost:8000
# Swagger: http://localhost:8000/docs"""))
story.append(Spacer(1, 6))
story.append(Paragraph("Frontend (separate terminal):", body))
story.append(code_block("""cd frontend
npm install
npm run dev               # http://localhost:3000"""))
story.append(Paragraph('If a run fails with <font face="Courier">table user_configs has no column named ...</font>, '
                       'delete <font face="Courier">backend/cvedb.sqlite</font> and restart &mdash; the dev DB '
                       "gets recreated with the current schema.", note))

# ── 3. Read the map ──
story.append(Paragraph("3. Read the map before touching code", h2))
story.append(ListFlowable([
    ListItem(Paragraph('<font face="Courier">CLAUDE.md</font> &mdash; architecture, routes, schema, '
                       "what's built vs. missing.", body)),
    ListItem(Paragraph('<font face="Courier">backend/main.py</font> &mdash; every API route.', body)),
    ListItem(Paragraph('<font face="Courier">backend/rss_parser.py</font> &mdash; feed/NVD fetchers.', body)),
    ListItem(Paragraph('<font face="Courier">frontend/src/components/Dashboard.tsx</font> &mdash; nearly the '
                       "whole UI (one big file &mdash; see CLAUDE.md's P4 for the planned split).", body)),
], bulletType="bullet", start="circle"))

# ── 4. Production layout ──
story.append(Paragraph("4. Know the production layout", h2))
story.append(Paragraph('Bare-metal on <font face="Courier">10.4.150.57</font> (no Docker, no root &mdash; '
                       "the vnotice user isn't a sudoer):", body))
svc_table = Table(
    [["Service", "Port", "Unit"],
     ["Backend (uvicorn, plain HTTP)", "8080", "vnotice-backend.service"],
     ["Frontend (Next.js, plain HTTP)", "4000", "vnotice-frontend.service"]],
    colWidths=[3.1 * inch, 0.8 * inch, 2.4 * inch],
)
svc_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b3a55")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 9.5),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f8")]),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c9ccd4")),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
]))
story.append(Spacer(1, 6))
story.append(svc_table)
story.append(Spacer(1, 8))
story.append(Paragraph("Both are systemd --user services (lingering enabled, so they survive logout/reboot "
                       'without a login session). Both serve plain HTTP (no TLS) &mdash; open '
                       '<font face="Courier">http://10.4.150.57:4000</font>.', body))

# ── 5. Ship a change ──
story.append(Paragraph("5. Ship a change", h2))
story.append(Paragraph("There's no CI/CD yet &mdash; deploys are manual, from Windows via PuTTY's CLI tools "
                       "(git bash recommended).", body))
story.append(Paragraph("<b>Backend:</b>", body))
story.append(code_block("""# 1. Syntax-check locally first
py -c "import ast; ast.parse(open('backend/main.py', encoding='utf-8').read())"

# 2. Upload
"/c/Program Files/PuTTY/pscp.exe" -batch -pw '<password>' backend/main.py \\
  vnotice@10.4.150.57:/home/vnotice/vnotice/backend/

# 3. Restart (MSYS_NO_PATHCONV=1 stops git-bash mangling the /run/user/... path)
MSYS_NO_PATHCONV=1 "/c/Program Files/PuTTY/plink.exe" -ssh -batch -pw '<password>' \\
  vnotice@10.4.150.57 "XDG_RUNTIME_DIR=/run/user/\\$(id -u) systemctl --user restart vnotice-backend"

# 4. Verify
curl -s http://10.4.150.57:8080/health/"""))
story.append(Spacer(1, 6))
story.append(Paragraph('<b>Frontend:</b> same upload step, then on the server run <font face="Courier">npm run '
                       'build</font> (needs <font face="Courier">nvm use 20</font> first) before restarting '
                       "vnotice-frontend &mdash; Next.js needs a rebuild, unlike the backend which just "
                       "re-executes the .py file.", body))
story.append(Paragraph('<b>Gotcha:</b> never <font face="Courier">pkill -f \'uvicorn main:app\'</font> over SSH '
                       "&mdash; the pattern matches the SSH shell's own command line and kills your connection "
                       '(exit 128). Use <font face="Courier">systemctl --user stop/restart</font> instead.', note))

# ── 6. Commit ──
story.append(Paragraph("6. Commit", h2))
story.append(Paragraph("Nothing auto-commits. Stage, commit, and push yourself when a change is ready &mdash; "
                       "ask before pushing if you're unsure it's wanted yet.", body))

doc.build(story)
print(f"wrote {OUT}")
