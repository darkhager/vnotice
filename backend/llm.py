"""The AI provider Vnotice uses to double-check extracted vulnerability details,
and where its API key is kept. Ported from Sabler (PM report generator,
webapp/llm.py) so both tools share one integration pattern and the same
provider list -- MFEC's own LiteLLM gateway first.

The key is registered on the Settings page and stored in backend/secrets.json:
Fernet-encrypted (crypto.py, same key as every other secret column), owner-only
permissions, never in git, never sent back to the browser -- the page only
learns THAT a key is saved and its last four characters.

Only the providers listed here can be chosen, each with a fixed base URL: a
free-text URL would let anyone who can open the page point the saved key at a
server of their choosing. All of them speak OpenAI-style chat completions.
"""
import json
import logging
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import crypto

logger = logging.getLogger("vnotice.llm")

SECRETS_PATH = Path(__file__).parent / "secrets.json"
_lock = threading.Lock()

MFEC_MODELS = ["claude-sonnet-5", "gpt-5", "gpt-5-mini", "gemini-3.5-flash", "gemini-3.7-flash", "gemini-3.8-flash",
               "gemini-3-flash", "deepseek-v4-pro", "deepseek-v4-flash", "glm-5.2", "glm-5.3-flash", "glm-5",
               "minimax-m3", "minimax-m2", "kimi-k2.7-code", "mimo-v2.5-pro", "tencent-hy4", "tencent-hy3"]

PROVIDERS = {
    "mfec": {"label": "MFEC AI gateway (LiteLLM)", "base": "https://gpt.mfec.co.th/litellm/v1",
             "model": "claude-sonnet-5", "verify_model": "gpt-5", "models": MFEC_MODELS},
    "gemini": {"label": "Google Gemini (free tier available)", "base": "https://generativelanguage.googleapis.com/v1beta/openai",
               "model": "gemini-2.0-flash"},
    "openai": {"label": "OpenAI", "base": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "groq": {"label": "Groq (free tier available)", "base": "https://api.groq.com/openai/v1",
             "model": "llama-3.3-70b-versatile"},
    "openrouter": {"label": "OpenRouter", "base": "https://openrouter.ai/api/v1",
                   "model": "meta-llama/llama-3.3-70b-instruct:free"},
    "anthropic": {"label": "Anthropic Claude", "base": "https://api.anthropic.com/v1",
                  "model": "claude-haiku-4-5-20251001"},
}


class LLMError(Exception):
    """A message fit to show the user (never contains the key)."""


def _read():
    try:
        return json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write(data):
    tmp = SECRETS_PATH.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, SECRETS_PATH)
    try:
        os.chmod(SECRETS_PATH, 0o600)
    except OSError:
        pass


def _key(cfg):
    enc = cfg.get("api_key_enc")
    if enc:
        key = crypto.decrypt(enc) or ""
        # decrypt() passes undecryptable data through unchanged instead of raising
        if key.startswith("enc::"):
            logger.error("saved AI key could not be decrypted (SECRET_KEY changed?)")
            return ""
        return key
    return os.environ.get("LLM_API_KEY", "")


def public_settings():
    """What the Settings page may see: never the key itself."""
    cfg = _read().get("llm", {})
    key = _key(cfg)
    return {
        "providers": [{"id": k, "label": v["label"], "model": v["model"],
                       "verify_model": v.get("verify_model", v["model"]), "models": v.get("models", [])}
                      for k, v in PROVIDERS.items()],
        "provider": cfg.get("provider", ""),
        "model": cfg.get("model", ""),
        "verify_model": cfg.get("verify_model", ""),
        "configured": bool(key),
        "key_hint": ("…" + key[-4:]) if len(key) >= 8 else ("saved" if key else ""),
    }


def save(provider, model, api_key, verify_model=""):
    """Save the choice; an empty api_key keeps the key already saved."""
    if provider not in PROVIDERS:
        raise LLMError("Choose one of the listed providers.")
    model = (model or "").strip() or PROVIDERS[provider]["model"]
    verify_model = (verify_model or "").strip() or PROVIDERS[provider].get("verify_model", model)
    with _lock:
        data = _read()
        old = data.get("llm", {})
        key = (api_key or "").strip()
        if not key:
            if old.get("provider") not in (None, provider):
                # a key belongs to the provider it was issued by
                raise LLMError("Enter the API key for this provider.")
            key = _key(old)
        if not key:
            raise LLMError("Enter the API key.")
        if any(c.isspace() for c in key) or len(key) < 8:
            raise LLMError("That doesn't look like an API key (no spaces, at least 8 characters).")
        data["llm"] = {"provider": provider, "model": model, "verify_model": verify_model,
                       "api_key_enc": crypto.encrypt(key)}
        _write(data)


def remove_key():
    with _lock:
        data = _read()
        data.pop("llm", None)
        _write(data)


def configured():
    return public_settings()["configured"]


def chat(messages, max_tokens=400, temperature=None, role="model"):
    """One chat-completions call with the saved provider; returns the reply
    text. role="verify" uses the second model, so a check is made by a
    different model than the one that produced the answer.

    temperature is omitted by default rather than sent as 0: some models behind
    the MFEC gateway (gpt-5, routed to Azure OpenAI) reject any temperature
    other than their own default of 1 (seen live in Sabler)."""
    cfg = _read().get("llm", {})
    key = _key(cfg)
    provider = PROVIDERS.get(cfg.get("provider", ""))
    if not key or provider is None:
        raise LLMError("No AI API key is registered yet (Settings → AI Verification).")
    model = (cfg.get("verify_model") if role == "verify" else cfg.get("model")) or provider["model"]
    payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
    if temperature is not None:
        payload["temperature"] = temperature
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(provider["base"] + "/chat/completions", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            reply = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise LLMError("The provider rejected the key (HTTP %d)." % e.code)
        if e.code == 429:
            raise LLMError("The provider says the quota or rate limit is used up (HTTP 429).")
        if e.code == 404:
            raise LLMError("The provider doesn't know that model name (HTTP 404).")
        detail = ""
        try:
            detail = json.loads(e.read()).get("error", {}).get("message", "")
        except Exception:                                  # noqa: BLE001
            pass
        raise LLMError(f"The provider returned HTTP {e.code}." + (f" {detail}" if detail else ""))
    except (urllib.error.URLError, OSError):
        raise LLMError("Could not reach the provider from the server.")
    try:
        return reply["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise LLMError("The provider's answer had an unexpected shape.")


def test():
    """Prove the saved key works with the cheapest possible call, for both models."""
    first = chat([{"role": "user", "content": "Reply with the single word OK."}], max_tokens=8).strip()
    second = chat([{"role": "user", "content": "Reply with the single word OK."}], max_tokens=8, role="verify").strip()
    return first + " / " + second
