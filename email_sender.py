# Send HTML/plain-text emails via SMTP

import os
import smtplib
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailSender:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.from_addr = os.getenv("SMTP_FROM", self.smtp_user)

    def _check_config(self):
        missing = [k for k, v in {
            "SMTP_HOST": self.smtp_host,
            "SMTP_USER": self.smtp_user,
            "SMTP_PASS": self.smtp_pass,
        }.items() if not v]
        if missing:
            raise RuntimeError(
                f"Email not configured. Missing env vars: {', '.join(missing)}. "
                "See .env.example for setup instructions."
            )

    def send(self, to_email: str, subject: str, body: str):
        self._check_config()

        html_body = _markdown_to_html(body)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.from_addr
        msg["To"]      = to_email

        msg.attach(MIMEText(body,      "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html",  "utf-8"))

        with smtplib.SMTP(self.smtp_host, self.smtp_port) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(self.smtp_user, self.smtp_pass)
            smtp.sendmail(self.from_addr, to_email, msg.as_string())


# ─── Minimal Markdown → HTML converter ───────────────────────────────────────

def _markdown_to_html(md: str) -> str:
    import re

    lines   = md.splitlines()
    out     = []
    in_list = False

    for line in lines:
        stripped = line.strip()

        # Headings
        if stripped.startswith("### "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h3>{_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h2>{_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h1>{_inline(stripped[2:])}</h1>")
        # List items
        elif stripped.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
        # Horizontal rule
        elif stripped == "---":
            if in_list: out.append("</ul>"); in_list = False
            out.append("<hr/>")
        # Blank line
        elif not stripped:
            if in_list: out.append("</ul>"); in_list = False
            out.append("<br/>")
        # Normal paragraph
        else:
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<p>{_inline(stripped)}</p>")

    if in_list:
        out.append("</ul>")

    body_content = "\n".join(out)
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<style>
  body      {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               max-width: 720px; margin: 40px auto; color: #1a1a1a; line-height: 1.6; }}
  h1        {{ border-bottom: 2px solid #d32f2f; padding-bottom: 8px; color: #d32f2f; }}
  h2        {{ margin-top: 28px; color: #333; }}
  h3        {{ color: #555; margin-top: 20px; }}
  li        {{ margin: 6px 0; }}
  code      {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px;
               font-family: monospace; font-size: 0.9em; }}
  hr        {{ border: none; border-top: 1px solid #eee; margin: 24px 0; }}
  .footer   {{ color: #999; font-size: 0.85em; margin-top: 40px; }}
</style>
</head>
<body>
{body_content}
</body>
</html>"""


def _inline(text: str) -> str:
    """Apply inline Markdown: **bold**, `code`, links."""
    import re
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`",        r"<code>\1</code>",     text)
    text = re.sub(
        r"(https?://[^\s)]+)",
        r'<a href="\1">\1</a>',
        text,
    )
    return text
