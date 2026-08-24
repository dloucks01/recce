"""Shared helpers extracted from tests/test_pipeline.py during its split."""
"""Offline tests for the enumeration pipeline (no network / nmap needed)."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad, exploits, parser, scanner
from recce import tracking as tr
from recce import xlsx
from recce.models import Account, Host, Port, Script, Vuln
from recce.report_excel import (build_workbook, read_workbook_tracking,
                                       update_workbook)
from recce.store import Store
from recce.targets import apply_exclusions, load_targets

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")


SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")




def header_index(rows, *must_have):
    """Row index of the real column-header row (first row holding every token in
    must_have). The Checklist puts a legend line above its header, so callers must
    locate it rather than assume row 0."""
    for i, r in enumerate(rows):
        if all(tok in r for tok in must_have):
            return i
    return 0




def _docx_text(path):
    import zipfile
    import xml.etree.ElementTree as ET
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():          # every xml part must be well-formed
            if n.endswith((".xml", ".rels")):
                ET.fromstring(z.read(n))
        root = ET.fromstring(z.read("word/document.xml"))
        parts = z.namelist()
    return "\n".join("".join(t.text or "" for t in p.iter(f"{W}t"))
                     for p in root.iter(f"{W}p")), parts




def _self_response():
    """Tiny well-formed GetResponse so a bare parse_response smoke-check has input."""
    from recce import snmp as S
    varbind = S._tlv(0x30, S.encode_oid("1.3.6.1.2.1.1.1.0") + S._octet("x"))
    pdu = S._tlv(0xA2, S._int(1) + S._int(0) + S._int(0) + S._tlv(0x30, varbind))
    return S._tlv(0x30, S._int(1) + S._octet("public") + pdu)
