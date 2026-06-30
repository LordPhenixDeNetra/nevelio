#!/usr/bin/env python3
"""
Nevelio Hardware Security — Python i18n engine.

Reads locale YAML files from hardware/python/locales/{lang}.yml.
Falls back to JSON if PyYAML is not installed.

Usage:
    from i18n import t, set_lang
    print(t("fw.report_written", path="/tmp/out.json", n=5))
    set_lang("en")
"""

import json
import os

_LOCALES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
_cache: dict[str, dict] = {}
_lang = "fr"


# ── Language detection ────────────────────────────────────────────────────────

def _detect_lang() -> str:
    for env in ("NEVELIO_LANG", "LANG", "LANGUAGE"):
        val = os.environ.get(env, "")
        code = val.split(".")[0].split("_")[0].lower()
        if code in ("fr", "en", "es"):
            return code
    return "fr"


def set_lang(lang: str) -> None:
    """Override detected language at runtime (e.g. from a --lang CLI flag)."""
    global _lang
    if lang in ("fr", "en", "es"):
        _lang = lang


# ── Locale loading ────────────────────────────────────────────────────────────

def _load(lang: str) -> dict:
    """Load and cache the locale file for `lang`. Returns an empty dict on error."""
    if lang in _cache:
        return _cache[lang]

    data: dict = {}
    yml_path  = os.path.join(_LOCALES_DIR, f"{lang}.yml")
    json_path = os.path.join(_LOCALES_DIR, f"{lang}.json")

    if os.path.exists(yml_path):
        try:
            import yaml  # PyYAML — pip install pyyaml
            with open(yml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except ImportError:
            # PyYAML absent → try JSON twin
            if os.path.exists(json_path):
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)
    elif os.path.exists(json_path):
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

    _cache[lang] = data
    return data


def _get(data: dict, key: str) -> str | None:
    """Dot-path lookup: 'fw.binwalk.missing.title' → nested dict traversal."""
    node = data
    for part in key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, str) else None


# ── Public API ────────────────────────────────────────────────────────────────

def t(__key: str, **kwargs) -> str:
    """
    Return the translation of `__key` in the current language.

    Falls back to French, then returns the key itself if not found.
    Supports {var} interpolation via kwargs.

    The first arg uses `__key` to avoid conflicts with kwargs like key=0x2b.

    Examples:
        t("fw.report_written", path="/tmp/out.json", n=5)
        t("cpa.byte_result", idx=0, key=0x2b, corr=0.98)
    """
    text = (_get(_load(_lang), __key)
            or _get(_load("fr"), __key)
            or __key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return text


# Auto-detect on import
_lang = _detect_lang()
