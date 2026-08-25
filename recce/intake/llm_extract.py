"""LLM-assisted parser drafting (P3b) — a genuine escape hatch for tool
output that doesn't match anything else and where writing a regex from
scratch is more friction than pasting a sample.

The tester pastes their tool's sample output; we prompt a local LLM
(Ollama by default) to return a parser spec in the same JSON schema Phase 2
already validates and loads. If the returned JSON validates, the tester
can review, tweak in the ImportModal form, and save.

## Endpoint

Env vars control the target:
* ``RECCE_LLM_URL`` — HTTP endpoint. Default ``http://localhost:11434/api/generate``
  (Ollama). Any endpoint accepting a POST with an OpenAI-compatible
  ``{model, prompt}`` payload works.
* ``RECCE_LLM_MODEL`` — model name. Default ``llama3.2``.
* ``RECCE_LLM_TIMEOUT_S`` — request timeout. Default 60.

We stdlib-post to Ollama's /api/generate. If the tester runs a
different provider (an OpenAI-compat chat/completions API), point
RECCE_LLM_URL at it — this module is unopinionated about the vendor.

## Safety

The LLM output is **never trusted directly**. Every response passes
through `parsers_user._validate`; a bad spec is rejected before it can
reach `parsers_user._make_parser`. The endpoint returns the draft to the
tester for review; nothing auto-registers.
"""
from __future__ import annotations

import json
import os
import urllib.request


_DEFAULT_URL = "http://localhost:11434/api/generate"
_DEFAULT_MODEL = "llama3.2"

_PROMPT_TEMPLATE = """You are helping author a JSON parser spec for a pentest-tool
importer called `recce`. The spec loads at runtime and extracts findings
from arbitrary tool output using named-capture regexes.

The tester will provide a sample of some tool's raw output. Your job is
to return ONLY a valid JSON object matching this schema:

{{
  "name": "<lowercase-kebab-case, 3-40 chars>",
  "description": "<one-sentence what this parser is for>",
  "detect": {{
    "content_substr": "<a stable substring that appears in this tool's output>",
    "content_re": "<optional confirming regex>"
  }},
  "match": {{
    "target_re": "<line-anchored regex with (?P<target>...) capturing the tool's target host/URL>",
    "port_default": <integer default port, or 0>
  }},
  "findings": [
    {{
      "marker_re": "<regex with (?P<title>...) and optionally (?P<ip>...), (?P<port>...), (?P<cve>CVE-\\\\d+-\\\\d+)>",
      "severity": "critical|high|medium|low|info",
      "confidence": "confirmed|likely|potential|info"
    }}
  ]
}}

Rules you must follow:
* Return ONLY the JSON object. No markdown fences, no prose before or after.
* Every regex must be anchored appropriately (^ / $) since parsing uses re.MULTILINE.
* Backslashes inside JSON strings must be doubled (\\\\d not \\d).
* Add ONE finding rule per distinct severity/format the sample shows.
* `title` is a required named group in every marker_re.
* Prefer fewer, higher-quality rules over noisy catch-alls.
* If you can't infer the target reliably, omit `target_re` and let the
  ImportModal ask the tester later.

Here is the sample the tester wants parsed:

--- BEGIN SAMPLE ---
{sample}
--- END SAMPLE ---

Reply with the JSON now."""


class LLMError(Exception):
    """Raised when the LLM call fails, times out, or the response can't be
    coerced into a valid parser spec."""


def draft_parser_spec(sample_text: str, hint: str = "") -> dict:
    """Call the configured LLM, parse the response, validate against the
    parser schema. Returns the spec dict on success; raises LLMError with
    a tester-friendly message on any failure."""
    url = os.environ.get("RECCE_LLM_URL", _DEFAULT_URL)
    model = os.environ.get("RECCE_LLM_MODEL", _DEFAULT_MODEL)
    timeout = float(os.environ.get("RECCE_LLM_TIMEOUT_S", "60"))
    prompt = _PROMPT_TEMPLATE.format(sample=sample_text[:8000])
    if hint:
        prompt += f"\n\nAdditional hint from the tester: {hint[:500]}"

    body = {"model": model, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.2}}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise LLMError(f"LLM endpoint returned {e.code}: {e.read()[:200].decode('utf-8','replace')}")
    except urllib.error.URLError as e:
        raise LLMError(f"LLM endpoint unreachable at {url}: {e.reason}. "
                       f"Set RECCE_LLM_URL, or install & start Ollama "
                       f"(ollama serve; ollama pull {model}).")
    except OSError as e:
        raise LLMError(f"LLM call failed: {e}")

    try:
        outer = json.loads(raw)
    except ValueError as e:
        raise LLMError(f"LLM response wasn't JSON: {e}")

    # Ollama nests the model's text under `response`; OpenAI-compat APIs
    # nest it under choices[0].message.content — try both.
    text = outer.get("response") or ""
    if not text and isinstance(outer.get("choices"), list) and outer["choices"]:
        text = (outer["choices"][0].get("message") or {}).get("content") or ""
    if not text:
        raise LLMError("LLM response had no text body")

    # Strip potential markdown fences the model added despite instructions.
    text = text.strip()
    if text.startswith("```"):
        # ```json\n{...}\n``` — drop the fence lines
        lines = text.splitlines()
        text = "\n".join(l for l in lines[1:] if not l.strip().startswith("```")).strip()

    try:
        spec = json.loads(text)
    except ValueError as e:
        # Return the raw text on the error so the tester can see what the
        # model actually produced and fix it themselves.
        raise LLMError(f"LLM output wasn't valid JSON ({e}). Raw response:\n\n{text[:1500]}")

    from .parsers_user import _validate
    ok, why = _validate(spec, "<llm-draft>")
    if not ok:
        raise LLMError(f"LLM-produced spec failed validation: {why}. "
                       f"Raw response:\n\n{json.dumps(spec, indent=2)[:1500]}")
    return spec
