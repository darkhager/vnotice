"""One-off: render the "set up a new user account" steps as a PDF."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.enums import TA_LEFT

OUT = "ACCOUNT_SETUP.pdf"

styles = getSampleStyleSheet()
title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=22, spaceAfter=4)
subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], textColor=colors.HexColor("#666666"), spaceAfter=20)
h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13.5, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1a1a1a"))
body = ParagraphStyle("BodyX", parent=styles["Normal"], fontSize=10.5, leading=15, spaceAfter=6, alignment=TA_LEFT)
note = ParagraphStyle("Note", parent=body, textColor=colors.HexColor("#8a5a00"), backColor=colors.HexColor("#fff6e0"),
                      borderPadding=8, spaceBefore=6, spaceAfter=10)

doc = SimpleDocTemplate(OUT, pagesize=letter,
                        topMargin=0.8 * inch, bottomMargin=0.8 * inch,
                        leftMargin=0.9 * inch, rightMargin=0.9 * inch)
story = []

story.append(Paragraph("Setting Up a New Account &mdash; Vnotice", title_style))
story.append(Paragraph("There's no separate sign-up screen &mdash; account creation happens inline, "
                       "in one panel, the first time someone links their alerts.", subtitle_style))

steps = [
    ('Open <b>Settings &rarr; Alert Channels</b>',
     'Find the panel titled <b>&ldquo;Link to Vnotice Alerts (server-side)&rdquo;</b> near the top.'),
    ('Enter email and choose a password',
     'Fill in the new user\'s <b>Email</b> and an <b>Account Password</b> in that panel. The password field\'s '
     'placeholder says it plainly: &ldquo;First time = creates the account.&rdquo;'),
    ('Click &ldquo;Link Account&rdquo;',
     'One button does both jobs: it first tries to log in with that email/password. If no account exists yet, '
     'it automatically registers one, then logs in &mdash; there is no separate sign-up form to fill out.'),
    ('Pick feed sources',
     'Once linked, the panel switches to a list of feed sources (Check Point, Fortinet, NVD, etc.). Check the ones '
     'this user wants alerted on.'),
    ('Click &ldquo;Save Alert Settings to Server&rdquo;',
     'This saves the selected feeds as real trigger rules on the server, so the hourly auto-sync job can alert '
     'this user even while their browser is closed.'),
    ('Fill in delivery details',
     'In the adjacent Email Alerts / Teams panels on the same Settings page, add SMTP or webhook details &mdash; '
     'the triggers saved in step 5 need somewhere to actually send to.'),
]

for i, (head, desc) in enumerate(steps, 1):
    story.append(Paragraph(f"{i}. {head}", h2))
    story.append(Paragraph(desc, body))

story.append(Paragraph("Getting a Teams webhook URL (needed for step 6, Teams alerts only)", h2))
story.append(Paragraph(
    'The Teams field\'s placeholder (<font face="Courier">https://...logic.azure.com/workflows/...</font>) '
    "expects a modern Power Automate <b>Workflow</b> URL, not an old-style connector. Whoever owns the target "
    "Teams channel sets this up, in Teams itself (web or desktop app):", body))
story.append(ListFlowable([
    ListItem(Paragraph("Open the channel that should receive alerts.", body)),
    ListItem(Paragraph('Click <b>&ldquo;&middot;&middot;&middot;&rdquo;</b> next to the channel name &rarr; '
                       '<b>Workflows</b> (search for the &ldquo;Workflows&rdquo; app if it isn\'t pinned).', body)),
    ListItem(Paragraph('Pick the template <b>&ldquo;Post to a channel when a webhook request is '
                       'received.&rdquo;</b>', body)),
    ListItem(Paragraph("Confirm the team/channel, then click <b>Add workflow</b>.", body)),
    ListItem(Paragraph("Teams generates a webhook URL &mdash; copy it.", body)),
    ListItem(Paragraph("Paste that URL into Vnotice's Teams webhook field and click <b>Send Test</b> to "
                       "confirm it before saving.", body)),
], bulletType="1", start="1"))
story.append(Paragraph(
    'Vnotice also still accepts the legacy <font face="Courier">*.webhook.office.com/webhookb2/...</font> '
    "classic connector URL, for tenants that still have it enabled &mdash; but Microsoft has been retiring "
    "that path tenant-by-tenant, so the Workflow steps above are the ones that'll reliably work for a new "
    "setup. Email alerts (SMTP) need no equivalent web-side setup.", body))

story.append(Paragraph(
    "No admin action is required &mdash; registration is fully self-service (there is no invite code or admin "
    "approval step), and a default alert configuration is created automatically for the new account.", body))

story.append(Paragraph(
    "<b>Rate limit:</b> login and registration are both capped at 5 attempts per 60 seconds per IP address. "
    "A mistyped password a few times in a row will trigger a &ldquo;too many attempts&rdquo; message for "
    "about a minute before it can be retried.", note))

doc.build(story)
print(f"wrote {OUT}")
