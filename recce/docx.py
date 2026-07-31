"""Minimal, dependency-free .docx writer (stdlib only).

A .docx is a ZIP of XML parts, just like the .xlsx writer in xlsx.py. This keeps
report generation runnable on an airgapped box with no Node/python-docx install.
It supports exactly what the finding write-ups need: a title, headings, labelled
fields, normal/italic/placeholder paragraphs, bullets and page breaks. The
tester opens the result in Word and pastes screenshots inline as usual.
"""

from __future__ import annotations

import os
import tempfile
import zipfile
import re
from xml.sax.saxutils import escape

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

# XML-1.0-illegal control chars: nmap NSE / banner evidence can carry these, and
# they would make Word refuse to open the .docx. Strip before escaping.
_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(text) -> str:
    return escape(_XML_ILLEGAL.sub("�", str(text)))

# Colours (hex, no #) - the light adaptation of the HTML previews' palette.
_PLACEHOLDER = "B00020"   # dark red for [TESTER: ...] prompts
_MUTED = "666666"
_LABEL = "5F6F6E"         # muted slate for field labels
_EVIDENCE_FILL = "EDF6F4"  # faint teal tint behind monospace evidence

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="png" ContentType="image/png"/>'
    '<Default Extension="jpg" ContentType="image/jpeg"/>'
    '<Default Extension="jpeg" ContentType="image/jpeg"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '</Types>'
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '</Relationships>'
)

_DOC_NS = (
    f'xmlns:w="{W}" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
)

_EMU_PER_PX = 9525          # at 96 DPI
_MAX_IMG_EMU = 6 * 914400   # 6 inches wide max


def _png_size(data: bytes) -> tuple[int, int]:
    """(width, height) in px from a PNG header, or a sane default."""
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        w = int.from_bytes(data[16:20], "big")
        h = int.from_bytes(data[20:24], "big")
        if w and h:
            return w, h
    return 800, 600

# Styles: Normal, Title, Heading1, Heading2 (built-ins so headings show in the
# navigation pane / a generated TOC).
_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:styles xmlns:w="{W}">'
    '<w:docDefaults><w:rPrDefault><w:rPr>'
    '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/>'
    '</w:rPr></w:rPrDefault></w:docDefaults>'
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
    '<w:name w:val="Normal"/></w:style>'
    '<w:style w:type="paragraph" w:styleId="Title">'
    '<w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:before="120" w:after="120"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="0E6E67"/><w:sz w:val="36"/></w:rPr></w:style>'
    # NB: child order in <w:pPr> is schema-enforced (CT_PPrGeneral):
    # pBdr -> spacing -> outlineLvl.
    '<w:style w:type="paragraph" w:styleId="Heading1">'
    '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>'
    '<w:pPr>'
    '<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="0E6E67"/></w:pBdr>'
    '<w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="0"/>'
    '</w:pPr><w:rPr><w:b/><w:color w:val="0E6E67"/><w:sz w:val="26"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading2">'
    '<w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:before="120" w:after="40"/><w:outlineLvl w:val="1"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="0A4F4A"/><w:sz w:val="24"/></w:rPr></w:style>'
    '</w:styles>'
)

_SECTPR = ('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
           '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
           'w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>')


def _run(text: str, bold=False, italic=False, color: str | None = None,
         mono: bool = False) -> str:
    props = ""
    if mono:                       # rFonts must lead the run properties
        props += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>'
    if bold:
        props += "<w:b/>"
    if italic:
        props += "<w:i/>"
    if color:
        props += f'<w:color w:val="{color}"/>'
    rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
    return (f"<w:r>{rpr}<w:t xml:space=\"preserve\">"
            f"{_esc(text)}</w:t></w:r>")


class Document:
    """Build a .docx from paragraphs, then save()."""

    def __init__(self) -> None:
        self._paras: list[str] = []
        self._media: list[tuple[str, bytes]] = []   # (filename, bytes)
        self._rels: list[tuple[str, str, str]] = [   # (id, type, target)
            ("rId1",
             "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
             "styles.xml")]

    def _p(self, body: str, style: str | None = None) -> None:
        ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        self._paras.append(f"<w:p>{ppr}{body}</w:p>")

    # --- content helpers --------------------------------------------------------

    def title(self, text: str) -> None:
        self._p(_run(text), "Title")

    def heading(self, text: str, level: int = 1) -> None:
        self._p(_run(text), f"Heading{level}")

    def para(self, text: str = "", *, bold=False, italic=False,
             color: str | None = None) -> None:
        self._p(_run(text, bold=bold, italic=italic, color=color) if text else "")

    def guidance(self, text: str) -> None:
        """Italic muted instructional text carried over from the template."""
        self._p(_run(text, italic=True, color=_MUTED))

    def placeholder(self, text: str) -> None:
        """A [TESTER: ...] prompt for the operator to fill in Word."""
        self._p(_run(f"[TESTER: {text}]", italic=True, color=_PLACEHOLDER))

    def field(self, label: str, value: str = "", placeholder: str = "",
              value_color: str | None = None, mono: bool = False) -> None:
        """A 'Label: value' line - muted-teal bold label, then the value (or a
        placeholder). `value_color` tints the value (e.g. severity); `mono`
        renders it in the evidence font (e.g. CVE/CWE ids)."""
        body = _run(f"{label}: ", bold=True, color=_LABEL)
        if value:
            body += _run(value, bold=bool(value_color), color=value_color, mono=mono)
        elif placeholder:
            body += _run(f"[TESTER: {placeholder}]", italic=True, color=_PLACEHOLDER)
        self._p(body)

    def mono_block(self, text: str) -> None:
        """Fixed-width evidence block; each line becomes its own paragraph."""
        for line in (text or "").splitlines() or [""]:
            body = (f'<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>'
                    f'<w:sz w:val="18"/></w:rPr>'
                    f'<w:t xml:space="preserve">{_esc(line)}</w:t></w:r>')
            self._p(f'<w:pPr><w:shd w:val="clear" w:fill="{_EVIDENCE_FILL}"/></w:pPr>'
                    f'{body}')

    def image(self, data: bytes, caption: str | None = None) -> None:
        """Embed a PNG/JPEG image inline (scaled to fit the page width)."""
        idx = len(self._media) + 1
        ext = "png"
        fname = f"image{idx}.{ext}"
        self._media.append((fname, data))
        rid = f"rId{len(self._rels) + 1}"
        self._rels.append((
            rid,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            f"media/{fname}"))
        w_px, h_px = _png_size(data)
        w_emu = w_px * _EMU_PER_PX
        h_emu = h_px * _EMU_PER_PX
        if w_emu > _MAX_IMG_EMU:
            h_emu = int(h_emu * _MAX_IMG_EMU / w_emu)
            w_emu = _MAX_IMG_EMU
        drawing = (
            '<w:r><w:drawing>'
            f'<wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{w_emu}" cy="{h_emu}"/>'
            '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
            f'<wp:docPr id="{idx}" name="Screenshot {idx}"/>'
            '<a:graphic><a:graphicData '
            'uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:pic><pic:nvPicPr>'
            f'<pic:cNvPr id="{idx}" name="{fname}"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/>'
            '<a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            '<pic:spPr><a:xfrm><a:off x="0" y="0"/>'
            f'<a:ext cx="{w_emu}" cy="{h_emu}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            '</pic:pic></a:graphicData></a:graphic>'
            '</wp:inline></w:drawing></w:r>'
        )
        self._paras.append(f"<w:p>{drawing}</w:p>")
        if caption:
            self.para(caption, italic=True, color=_MUTED)

    def table(self, header: list[str], rows: list[list[str]],
              widths: list[int] | None = None) -> None:
        """A bordered table with a shaded header row. Widths in DXA (sum ~9360)."""
        ncol = len(header)
        if not widths:
            widths = [9360 // ncol] * ncol
        borders = "".join(
            f'<w:{e} w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>'
            for e in ("top", "left", "bottom", "right", "insideH", "insideV"))
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)

        def cell(text, w, *, is_header=False):
            shd = ('<w:shd w:val="clear" w:color="auto" w:fill="D7ECEA"/>'
                   if is_header else "")
            rpr = '<w:rPr><w:b/><w:color w:val="0A4F4A"/></w:rPr>' if is_header else ""
            run = (f'<w:r>{rpr}<w:t xml:space="preserve">{_esc(text)}'
                   f'</w:t></w:r>') if str(text) else ""
            return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{shd}'
                    f'<w:vAlign w:val="center"/></w:tcPr><w:p>{run}</w:p></w:tc>')

        trs = ['<w:tr>' + "".join(cell(h, widths[i], is_header=True)
                                  for i, h in enumerate(header)) + '</w:tr>']
        for row in rows:
            trs.append('<w:tr>' + "".join(
                cell(row[i] if i < len(row) else "", widths[i])
                for i in range(ncol)) + '</w:tr>')
        self._paras.append(
            f'<w:tbl><w:tblPr><w:tblW w:w="{sum(widths)}" w:type="dxa"/>'
            f'<w:tblBorders>{borders}</w:tblBorders></w:tblPr>'
            f'<w:tblGrid>{grid}</w:tblGrid>{"".join(trs)}</w:tbl>')
        self.para("")   # Word wants a paragraph after a table

    def page_break(self) -> None:
        self._paras.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    # --- output -----------------------------------------------------------------

    def _document_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document {_DOC_NS}><w:body>'
            + "".join(self._paras) + _SECTPR +
            '</w:body></w:document>'
        )

    def _doc_rels_xml(self) -> str:
        rels = "".join(
            f'<Relationship Id="{i}" Type="{t}" Target="{escape(tgt)}"/>'
            for i, t, tgt in self._rels)
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{rels}</Relationships>')

    def save(self, path: str) -> str:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(suffix=".docx", dir=parent)
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("[Content_Types].xml", _CONTENT_TYPES)
                z.writestr("_rels/.rels", _ROOT_RELS)
                z.writestr("word/_rels/document.xml.rels", self._doc_rels_xml())
                z.writestr("word/styles.xml", _STYLES)
                z.writestr("word/document.xml", self._document_xml())
                for fname, data in self._media:
                    z.writestr(f"word/media/{fname}", data)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return path
