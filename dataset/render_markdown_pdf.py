from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Preformatted,
    ListFlowable,
    ListItem,
    PageBreak,
)


def build_styles():
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=16,
            alignment=TA_LEFT,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1d4ed8"),
            spaceBefore=8,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "H3",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#111827"),
            spaceBefore=6,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=13,
            textColor=colors.HexColor("#111827"),
            spaceAfter=5,
        ),
        "code": ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8.2,
            leading=10,
            backColor=colors.HexColor("#f3f4f6"),
            borderPadding=6,
            borderWidth=0.5,
            borderColor=colors.HexColor("#d1d5db"),
            spaceAfter=8,
        ),
    }


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def inline_md(text: str) -> str:
    text = esc(text)
    text = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def render(markdown: str, out_path: Path):
    styles = build_styles()
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="Smart SIEM Documentation",
    )

    story = []
    lines = markdown.splitlines()
    in_code = False
    code_lines: list[str] = []
    list_buffer: list[str] = []

    def flush_list():
        nonlocal list_buffer
        if not list_buffer:
            return
        items = [
            ListItem(Paragraph(inline_md(item), styles["body"]), leftIndent=10)
            for item in list_buffer
        ]
        story.append(ListFlowable(items, bulletType="bullet", leftIndent=12))
        story.append(Spacer(1, 4))
        list_buffer = []

    for raw in lines:
        line = raw.rstrip("\n")

        if line.startswith("```"):
            flush_list()
            if not in_code:
                in_code = True
                code_lines = []
            else:
                story.append(Preformatted("\n".join(code_lines), styles["code"]))
                in_code = False
                code_lines = []
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            flush_list()
            story.append(Spacer(1, 4))
            continue

        if line.startswith("# "):
            flush_list()
            story.append(Paragraph(inline_md(line[2:]), styles["title"]))
            continue
        if line.startswith("## "):
            flush_list()
            title = line[3:]
            if story:
                story.append(Spacer(1, 6))
            story.append(Paragraph(inline_md(title), styles["h1"]))
            continue
        if line.startswith("### "):
            flush_list()
            story.append(Paragraph(inline_md(line[4:]), styles["h2"]))
            continue
        if line.startswith("#### "):
            flush_list()
            story.append(Paragraph(inline_md(line[5:]), styles["h3"]))
            continue

        if re.match(r"^\s*-\s+", line):
            list_buffer.append(line.split("-", 1)[1].strip())
            continue

        if re.match(r"^\d+\.\s+", line):
            flush_list()
            story.append(Paragraph(inline_md(line), styles["body"]))
            continue

        if line.strip() == "---":
            flush_list()
            story.append(PageBreak())
            continue

        flush_list()
        story.append(Paragraph(inline_md(line), styles["body"]))

    flush_list()

    if in_code and code_lines:
        story.append(Preformatted("\n".join(code_lines), styles["code"]))

    def add_page_number(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawRightString(A4[0] - 1.6 * cm, 1.0 * cm, f"Page {_doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 render_markdown_pdf.py input.md output.pdf")
        raise SystemExit(1)

    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    render(src.read_text(encoding="utf-8"), dst)
    print(dst)


if __name__ == "__main__":
    main()
