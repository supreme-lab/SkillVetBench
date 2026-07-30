"""
llm_client.py
=============
Unified LLM client supporting every major backend.

OPEN-SOURCE (HuggingFace)
  api_type="hf_local"   — load model weights locally via `transformers`
  api_type="hf_api"     — HuggingFace Inference API (serverless or dedicated endpoint)
  api_type="hf_router"  — HuggingFace router (https://router.huggingface.co/v1),
                          an OpenAI-compatible endpoint that forwards to whichever
                          provider is named in the model string, e.g.
                          "moonshotai/Kimi-K3:together". Auth via HF_TOKEN.

FRONTIER (API)
  api_type="anthropic"  — Anthropic Claude
  api_type="openai"     — OpenAI GPT / any OpenAI-compatible endpoint
                          (Together AI, Groq, Fireworks, LM Studio, vLLM, etc.)
  api_type="openrouter" — OpenRouter (routes to Anthropic/OpenAI/Meta/etc. models
                          via one API key, base_url=https://openrouter.ai/api/v1)
  api_type="ollama"     — Local Ollama server (also open-source)

Quick-start examples
────────────────────
  from llm_client import LLMClient, list_recommended_models

  # HuggingFace — download & run locally (GPU or CPU)
  client = LLMClient(api_type="hf_local",
                     model="meta-llama/Meta-Llama-3.1-8B-Instruct")

  # HuggingFace Inference API — pay-per-token hosted inference
  client = LLMClient(api_type="hf_api",
                     api_key="hf_...",
                     model="meta-llama/Meta-Llama-3.1-70B-Instruct")

  # HuggingFace Dedicated Inference Endpoint
  client = LLMClient(api_type="hf_api",
                     api_key="hf_...",
                     base_url="https://YOUR-ENDPOINT.huggingface.cloud")

  # Anthropic Claude
  client = LLMClient(api_type="anthropic", api_key="sk-ant-...")

  # OpenAI
  client = LLMClient(api_type="openai", api_key="sk-...")

  # OpenRouter (any model on openrouter.ai, one API key)
  client = LLMClient(api_type="openrouter",
                     api_key="sk-or-v1-...",
                     model="anthropic/claude-sonnet-4-6")

  # Together AI (OpenAI-compatible)
  client = LLMClient(api_type="openai",
                     api_key="...",
                     base_url="https://api.together.xyz/v1",
                     model="meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo")

  # Groq (fast, OpenAI-compatible)
  client = LLMClient(api_type="openai",
                     api_key="gsk_...",
                     base_url="https://api.groq.com/openai/v1",
                     model="llama-3.1-70b-versatile")

  # Ollama (local)
  client = LLMClient(api_type="ollama", model="llama3.1:8b")

  # HuggingFace router — one HF_TOKEN, routes to the provider named in the
  # model string (here: Together AI hosting Kimi-K3)
  client = LLMClient(api_type="hf_router", model="moonshotai/Kimi-K3:together")
"""

import json
import logging
import os
from typing import Optional

logger = logging.getLogger("SkillEval")

# ─── Recommended models per backend ─────────────────────────────────────────

RECOMMENDED_MODELS = {
    "hf_local": [
        ("meta-llama/Meta-Llama-3.1-8B-Instruct",    "Best open-source for instruction following  ~16 GB RAM"),
        ("meta-llama/Meta-Llama-3.1-70B-Instruct",   "Strongest reasoning  ~140 GB RAM or 2x80 GB GPU"),
        ("mistralai/Mistral-7B-Instruct-v0.3",        "Fast, reliable JSON output  ~14 GB RAM"),
        ("mistralai/Mixtral-8x7B-Instruct-v0.1",      "MoE architecture, strong reasoning  ~48 GB RAM"),
        ("Qwen/Qwen2.5-7B-Instruct",                  "Excellent JSON following, multilingual  ~14 GB RAM"),
        ("Qwen/Qwen2.5-14B-Instruct",                 "Strong security reasoning  ~28 GB RAM"),
        ("microsoft/Phi-3.5-mini-instruct",           "Tiny but capable, CPU-friendly  ~8 GB RAM"),
        ("google/gemma-2-9b-it",                      "Google open model  ~18 GB RAM"),
        ("deepseek-ai/DeepSeek-R1-Distill-Llama-8B",  "Strong reasoning via distillation  ~16 GB RAM"),
        ("NousResearch/Hermes-3-Llama-3.1-8B",        "Fine-tuned for structured output  ~16 GB RAM"),
    ],
    "hf_api": [
        ("meta-llama/Meta-Llama-3.1-70B-Instruct",   "Best quality on HF serverless"),
        ("meta-llama/Meta-Llama-3.1-8B-Instruct",    "Fast and affordable on HF serverless"),
        ("mistralai/Mixtral-8x7B-Instruct-v0.1",      "Strong JSON output on HF serverless"),
        ("mistralai/Mistral-7B-Instruct-v0.3",        "Lightweight on HF serverless"),
        ("Qwen/Qwen2.5-72B-Instruct",                 "Excellent structured tasks on HF API"),
        ("google/gemma-2-27b-it",                     "Strong Google open model on HF API"),
    ],
    "anthropic": [
        ("claude-opus-4-6",            "Most capable, best for complex security analysis"),
        ("claude-sonnet-4-6",          "Balanced speed/quality — recommended default"),
        ("claude-haiku-4-5-20251001",  "Fastest, good for bulk evaluation"),
    ],
    "openai": [
        ("gpt-4o",          "OpenAI flagship, strong reasoning"),
        ("gpt-4o-mini",     "Fast and affordable OpenAI model"),
        ("llama-3.1-70b-versatile",                         "Via Groq  base_url=https://api.groq.com/openai/v1"),
        ("meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo",  "Via Together AI  base_url=https://api.together.xyz/v1"),
        ("mistralai/Mistral-7B-Instruct-v0.3",               "Via Together AI"),
    ],
    "openrouter": [
        ("anthropic/claude-sonnet-4-6",  "Balanced speed/quality via OpenRouter"),
        ("openai/gpt-4o",                "OpenAI flagship via OpenRouter"),
        ("openai/gpt-4o-mini",           "Fast and affordable via OpenRouter"),
        ("meta-llama/llama-3.1-70b-instruct", "Strong open-source via OpenRouter"),
        ("google/gemini-2.0-flash-001",  "Fast Google model via OpenRouter"),
        ("deepseek/deepseek-chat",       "Cheap strong reasoning via OpenRouter"),
    ],
    "ollama": [
        ("llama3.1:8b",   "Default — well-rounded"),
        ("llama3.1:70b",  "Higher quality"),
        ("mistral:7b",    "Fast JSON output"),
        ("mixtral:8x7b",  "Strong reasoning"),
        ("qwen2.5:7b",    "Good structured output"),
        ("phi3.5:mini",   "Lightweight"),
    ],
    "hf_router": [
        ("moonshotai/Kimi-K3:together",   "Kimi K3 via Together AI, routed through HF"),
        ("deepseek-ai/DeepSeek-V3:novita", "DeepSeek V3 via Novita, routed through HF"),
    ],
}


def list_recommended_models():
    """Print all recommended models grouped by backend."""
    print("\n" + "="*72)
    print("  RECOMMENDED MODELS BY BACKEND")
    print("="*72)
    labels = {
        "hf_local":  "HuggingFace LOCAL   --api hf_local   (runs on your machine)",
        "hf_api":    "HuggingFace API     --api hf_api     (hosted inference)",
        "anthropic": "Anthropic Claude    --api anthropic  (frontier)",
        "openai":    "OpenAI / Compatible --api openai     (frontier + Together/Groq)",
        "openrouter":"OpenRouter          --api openrouter (routes to many providers)",
        "ollama":    "Ollama local        --api ollama     (local server)",
        "hf_router": "HF Router           --api hf_router  (HF-hosted routing to Together/Novita/etc.)",
    }
    for key, entries in RECOMMENDED_MODELS.items():
        print(f"\n  [{labels[key]}]")
        for model_id, desc in entries:
            print(f"    --model {model_id:<50s}  {desc}")
    print()


# ─── Main client class ───────────────────────────────────────────────────────

class LLMClient:
    """Unified interface for all LLM backends."""

    DEFAULTS = {
        "anthropic":  "claude-sonnet-4-6",
        "openai":     "gpt-4o-mini",
        "openrouter": "anthropic/claude-sonnet-4-6",
        "ollama":     "llama3.1:8b",
        "hf_local":   "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "hf_api":     "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "hf_router":  "moonshotai/Kimi-K3:together",
    }

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    HF_ROUTER_BASE_URL  = "https://router.huggingface.co/v1"
    OLLAMA_TIMEOUT = 600  # seconds — local generation (large max_tokens, reasoning
                          # models, cold model-load) is often much slower than a
                          # hosted API, so this needs more headroom than 180s.

    def __init__(
        self,
        api_type:     str           = "anthropic",
        api_key:      Optional[str] = None,
        model:        Optional[str] = None,
        base_url:     Optional[str] = None,
        max_tokens:   int           = 4096,
        temperature:  float         = 0.1,
        # HuggingFace local options
        device:       Optional[str] = None,   # "cuda" | "mps" | "cpu" | None=auto
        load_in_4bit: bool          = False,  # 4-bit quantization (bitsandbytes)
        load_in_8bit: bool          = False,  # 8-bit quantization (bitsandbytes)
        hf_cache_dir: Optional[str] = None,   # custom HF model cache path
        trust_remote_code: bool = False,      # execute custom modeling code
                                               # shipped in the HF repo — some
                                               # models (e.g. Kimi-K2.6) require
                                               # this to load at all. Off by
                                               # default: it runs arbitrary
                                               # code from the model repo.
    ):
        self.api_type     = api_type.lower()
        self.api_key      = api_key
        self.model        = model or self.DEFAULTS.get(self.api_type)
        self.base_url     = base_url
        self.max_tokens   = max_tokens
        self.temperature  = temperature
        self.device       = device
        self.load_in_4bit = load_in_4bit
        self.load_in_8bit = load_in_8bit
        self.hf_cache_dir = hf_cache_dir
        self.trust_remote_code = trust_remote_code

        # Lazy-loaded transformers pipeline (hf_local only)
        self._hf_pipeline = None
        # Lazy-loaded AutoModel/AutoProcessor pair for hf_local repos whose
        # custom code isn't pipeline()-compatible (e.g. AutoModel-only repos).
        self._hf_manual  = None
        self._hf_mode    = None   # "pipeline" | "manual"

        valid = set(self.DEFAULTS.keys())
        if self.api_type not in valid:
            raise ValueError(
                f"Unknown api_type: {self.api_type!r}. "
                f"Valid options: {sorted(valid)}"
            )

        if self.api_type == "ollama" and not self.base_url:
            self.base_url = self._resolve_ollama_base_url()

        if self.api_type == "openrouter" and not self.base_url:
            self.base_url = self.OPENROUTER_BASE_URL

        if self.api_type == "hf_router" and not self.base_url:
            self.base_url = self.HF_ROUTER_BASE_URL

        self._resolve_api_key()

    # ── Ollama host resolution ────────────────────────────────────────────────

    @staticmethod
    def _resolve_ollama_base_url() -> str:
        """
        Resolve the local Ollama server address.

        Honours the OLLAMA_HOST env var (the same variable `ollama serve` /
        the `ollama` CLI use), so a non-default `ollama serve` port/host is
        picked up automatically. Falls back to the standard localhost:11434.
        """
        host = os.getenv("OLLAMA_HOST", "").strip()
        if not host:
            return "http://localhost:11434"

        if "://" not in host:
            host = f"http://{host}"

        # 0.0.0.0 means "listen on all interfaces" — not a valid client target
        # on every platform, so rewrite it to a connectable loopback address.
        host = host.replace("://0.0.0.0:", "://127.0.0.1:").replace("://0.0.0.0", "://127.0.0.1")
        return host

    # ── API key resolution ───────────────────────────────────────────────────

    def _resolve_api_key(self):
        ENV_MAP = {
            "anthropic":  "ANTHROPIC_API_KEY",
            "openai":     "OPENAI_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "hf_api":     "HF_TOKEN",
            "hf_local":   "HF_TOKEN",       # needed for gated models (Llama etc.)
            "hf_router":  "HF_TOKEN",
        }
        if self.api_type in ENV_MAP and not self.api_key:
            self.api_key = os.getenv(ENV_MAP[self.api_type], "")

        if self.api_type == "anthropic" and not self.api_key:
            raise ValueError(
                "Anthropic API key missing.\n"
                "  Option 1: export ANTHROPIC_API_KEY=sk-ant-...\n"
                "  Option 2: python main.py ... --key sk-ant-..."
            )
        if self.api_type == "openai" and not self.api_key:
            raise ValueError(
                "OpenAI API key missing.\n"
                "  Option 1: export OPENAI_API_KEY=sk-...\n"
                "  Option 2: python main.py ... --key sk-..."
            )
        if self.api_type == "openrouter" and not self.api_key:
            raise ValueError(
                "OpenRouter API key missing.\n"
                "  Option 1: export OPENROUTER_API_KEY=sk-or-v1-...\n"
                "  Option 2: python main.py ... --key sk-or-v1-..."
            )
        if self.api_type == "hf_api" and not self.api_key:
            logger.warning(
                "HF_TOKEN not set. Public models work without a token, but "
                "gated models (Llama 3, Mistral, etc.) require authentication.\n"
                "  export HF_TOKEN=hf_...   or   python main.py ... --key hf_..."
            )
        if self.api_type == "hf_router" and not self.api_key:
            raise ValueError(
                "HF_TOKEN missing — required by the HuggingFace router.\n"
                "  Option 1: export HF_TOKEN=hf_...\n"
                "  Option 2: python main.py ... --key hf_..."
            )

    # ── Public interface ─────────────────────────────────────────────────────

    def complete(self, system_prompt: str, user_message: str) -> str:
        """Send a system + user turn, return the assistant response as a string."""
        return {
            "anthropic":  self._anthropic,
            "openai":     self._openai_compat,
            "openrouter": self._openrouter,
            "ollama":     self._ollama,
            "hf_local":   self._hf_local,
            "hf_api":     self._hf_api,
            "hf_router":  self._hf_router,
        }[self.api_type](system_prompt, user_message)

    # ── Anthropic ────────────────────────────────────────────────────────────

    def _anthropic(self, system: str, user: str) -> str:
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install anthropic")
        client = anthropic.Anthropic(api_key=self.api_key)
        resp   = client.messages.create(
            model      = self.model,
            max_tokens = self.max_tokens,
            system     = system,
            messages   = [{"role": "user", "content": user}],
        )
        return resp.content[0].text.strip()

    # ── OpenAI / compatible ──────────────────────────────────────────────────

    def _openai_compat(self, system: str, user: str) -> str:
        try:
            import openai
        except ImportError:
            raise ImportError("pip install openai")
        kwargs = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = openai.OpenAI(**kwargs)
        resp   = client.chat.completions.create(
            model       = self.model,
            max_tokens  = self.max_tokens,
            temperature = self.temperature,
            messages    = [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return resp.choices[0].message.content.strip()

    # ── OpenRouter ───────────────────────────────────────────────────────────

    def _openrouter(self, system: str, user: str) -> str:
        """
        OpenRouter — OpenAI-compatible endpoint that routes to many providers
        (Anthropic, OpenAI, Meta, Google, DeepSeek, etc.) via one API key.
        Model names are provider-prefixed, e.g. "anthropic/claude-sonnet-4-6".
        """
        try:
            import openai
        except ImportError:
            raise ImportError("pip install openai")
        client = openai.OpenAI(
            api_key  = self.api_key,
            base_url = self.base_url or self.OPENROUTER_BASE_URL,
            default_headers = {
                "HTTP-Referer": "https://github.com/supreme-lab/SkillVetBench",
                "X-Title":      "SkillVetBench",
            },
        )
        resp = client.chat.completions.create(
            model       = self.model,
            max_tokens  = self.max_tokens,
            temperature = self.temperature,
            messages    = [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return resp.choices[0].message.content.strip()

    # ── HuggingFace router ───────────────────────────────────────────────────

    def _hf_router(self, system: str, user: str) -> str:
        """
        HuggingFace router — an OpenAI-compatible endpoint at
        https://router.huggingface.co/v1 that forwards to whichever inference
        provider is named after the colon in the model string, e.g.
        "moonshotai/Kimi-K3:together" -> served by Together AI. One HF_TOKEN
        covers every provider the router supports.
        """
        try:
            import openai
        except ImportError:
            raise ImportError("pip install openai")
        client = openai.OpenAI(
            api_key  = self.api_key,
            base_url = self.base_url or self.HF_ROUTER_BASE_URL,
        )
        resp = client.chat.completions.create(
            model       = self.model,
            max_tokens  = self.max_tokens,
            temperature = self.temperature,
            messages    = [
                {"role": "system", "content": [{"type": "text", "text": system}]},
                {"role": "user",   "content": [{"type": "text", "text": user}]},
            ],
        )
        return resp.choices[0].message.content.strip()

    # ── Ollama ───────────────────────────────────────────────────────────────

    def _ollama(self, system: str, user: str) -> str:
        import urllib.request, urllib.error
        url     = f"{self.base_url.rstrip('/')}/api/chat"
        payload = json.dumps({
            "model": self.model, "stream": False,
            # Keep the model resident for the whole batch run — without this,
            # Ollama's default eviction window is short enough that gaps
            # between skills trigger a full reload (~20-30s) before every call.
            "keep_alive": "30m",
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                # Skill-evaluation prompts run well under 10K tokens; capping
                # num_ctx avoids paying for the model's full 131K-token default
                # KV-cache allocation (which otherwise slows down every load).
                "num_ctx": 32768,
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.OLLAMA_TIMEOUT) as resp:
                return json.loads(resp.read())["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            # Server is reachable but returned an error (bad model, load failure,
            # context overflow, etc.) — surface Ollama's own message, not a
            # generic "unreachable" one. HTTPError is a URLError subclass, so
            # it must be caught before the broader except below.
            body = e.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(body).get("error", body)
            except (json.JSONDecodeError, AttributeError):
                detail = body
            raise RuntimeError(
                f"Ollama returned HTTP {e.code} for model '{self.model}' at {self.base_url}.\n"
                f"Error: {detail}"
            )
        except TimeoutError:
            # NOTE: TimeoutError and urllib.error.URLError are sibling OSError
            # subclasses — neither catches the other — so this needs its own
            # clause or a slow response surfaces as a bare, contextless
            # "timed out" instead of this actionable message.
            raise TimeoutError(
                f"Ollama request timed out after {self.OLLAMA_TIMEOUT}s for model "
                f"'{self.model}' at {self.base_url}.\n"
                f"The model may still be loading (large local models can take a "
                f"minute+ on first request) or generation is slow for this "
                f"hardware — try again, use a smaller model, or lower --max-tokens."
            )
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot reach Ollama at {self.base_url}.\n"
                f"Run: ollama serve && ollama pull {self.model}\nError: {e}"
            )

    # ── HuggingFace LOCAL ────────────────────────────────────────────────────

    def _hf_local(self, system: str, user: str) -> str:
        """
        Runs the model locally using the `transformers` library.
        Model weights are downloaded on the first call and cached.

        Install:
            pip install transformers torch accelerate
            pip install bitsandbytes   # for 4-bit / 8-bit quantization
        """
        if self._hf_mode is None:
            # Decide the loading strategy ONCE, from lightweight config
            # metadata only (no weight download) — deciding wrong here would
            # mean downloading multi-hundred-GB weights twice.
            self._hf_mode = "manual" if self._needs_manual_hf_loading() else "pipeline"

        if self._hf_mode == "pipeline":
            if self._hf_pipeline is None:
                self._hf_pipeline = self._build_hf_pipeline()
            return self._generate_hf_pipeline(system, user)

        if self._hf_manual is None:
            self._hf_manual = self._build_hf_manual()
        return self._generate_hf_manual(system, user)

    def _generate_hf_pipeline(self, system: str, user: str) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]
        try:
            outputs = self._hf_pipeline(
                messages,
                max_new_tokens  = self.max_tokens,
                temperature     = self.temperature,
                do_sample       = self.temperature > 0,
                pad_token_id    = self._hf_pipeline.tokenizer.eos_token_id,
                return_full_text= False,
            )
            result = outputs[0]["generated_text"]
            # Chat-format pipeline returns a list of message dicts
            if isinstance(result, list):
                for msg in reversed(result):
                    if isinstance(msg, dict) and msg.get("role") == "assistant":
                        return msg["content"].strip()
            return str(result).strip()
        except Exception as e:
            raise RuntimeError(f"HF local inference error: {e}")

    def _needs_manual_hf_loading(self) -> bool:
        """
        Some trust_remote_code repos register only an `AutoModel` entry (often
        multimodal/base-class repos) with no `AutoModelForCausalLM` mapping —
        `pipeline("text-generation", ...)` can't load those at all. Detect
        this from the repo's config.json only (auto_map), never from weights,
        so a wrong guess never costs a duplicate download of a huge model.
        """
        if not self.trust_remote_code:
            return False  # only custom (auto_map-based) repos need this check
        try:
            from transformers import AutoConfig
            config = AutoConfig.from_pretrained(
                self.model, trust_remote_code=True, token=self.api_key or None,
            )
        except Exception as e:
            logger.debug(f"  Could not pre-check config for '{self.model}': {e}")
            return False  # fall back to the normal pipeline path and let it error clearly

        auto_map = getattr(config, "auto_map", None) or {}
        has_causal_lm = "AutoModelForCausalLM" in auto_map
        has_base_model = "AutoModel" in auto_map
        if has_base_model and not has_causal_lm:
            logger.info(
                f"  '{self.model}' declares AutoModel (not AutoModelForCausalLM) "
                f"in its custom code — using the AutoModel/AutoProcessor path."
            )
            return True
        return False

    def _build_hf_manual(self):
        """
        Load via AutoProcessor + AutoModel for repos whose custom code isn't
        pipeline()-compatible (see _needs_manual_hf_loading). Mirrors the
        device/quantization strategy in _build_hf_pipeline.
        """
        try:
            from transformers import AutoModel, AutoProcessor
            import torch
        except ImportError:
            raise ImportError(
                "Install GPU dependencies first:\n"
                "  pip install transformers torch accelerate\n"
                "  pip install bitsandbytes   # for 4-bit/8-bit quantization"
            )

        logger.info(f"  Loading (AutoModel/AutoProcessor): {self.model}")

        device, n_gpus, total_vram_gb = self._detect_device(torch)
        if device == "cuda" and not self.load_in_4bit and not self.load_in_8bit:
            self._check_vram_and_warn(total_vram_gb)

        quant_config = None
        if self.load_in_4bit or self.load_in_8bit:
            quant_config = self._build_quant_config(torch)

        model_kwargs = {}
        if device in ("cuda", "mps"):
            model_kwargs["torch_dtype"] = torch.float16
        elif device == "cpu":
            model_kwargs["torch_dtype"] = torch.float32
        if quant_config:
            model_kwargs["quantization_config"] = quant_config
        if device == "cuda":
            model_kwargs["device_map"] = "auto"
        if self.hf_cache_dir:
            model_kwargs["cache_dir"] = self.hf_cache_dir

        if self.trust_remote_code:
            logger.warning(
                f"  ⚠  trust_remote_code=True — executing custom Python code "
                f"shipped in the '{self.model}' HF repo. Only enable this for "
                f"models you trust."
            )

        try:
            processor = AutoProcessor.from_pretrained(
                self.model, trust_remote_code=self.trust_remote_code,
                token=self.api_key or None,
            )
            model = AutoModel.from_pretrained(
                self.model, trust_remote_code=self.trust_remote_code,
                token=self.api_key or None, **model_kwargs,
            )
            logger.info(f"  Model ready on {device.upper()}")
            return processor, model
        except Exception as e:
            raise self._build_load_error(str(e), device)

    def _generate_hf_manual(self, system: str, user: str) -> str:
        processor, model = self._hf_manual
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]
        try:
            inputs = processor.apply_chat_template(
                messages,
                add_generation_prompt=True,
                tokenize=True,
                return_dict=True,
                return_tensors="pt",
            ).to(model.device)
            outputs = model.generate(
                **inputs,
                max_new_tokens=self.max_tokens,
                temperature=self.temperature,
                do_sample=self.temperature > 0,
            )
            new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
            return processor.decode(new_tokens, skip_special_tokens=True).strip()
        except Exception as e:
            raise RuntimeError(f"HF local (manual AutoModel) inference error: {e}")

    def _build_hf_pipeline(self):
        """
        Download (or load from cache) and initialise the transformers pipeline.
        Automatically selects the best GPU strategy based on available hardware.
        """
        try:
            from transformers import pipeline
            import torch
        except ImportError:
            raise ImportError(
                "Install GPU dependencies first:\n"
                "  pip install transformers torch accelerate\n"
                "  pip install bitsandbytes   # for 4-bit/8-bit quantization\n"
                "Run check_gpu.py to get the exact install command for your hardware."
            )

        logger.info(f"  Loading: {self.model}")

        # ── Detect device & VRAM ──────────────────────────────────────
        device, n_gpus, total_vram_gb = self._detect_device(torch)

        # ── Auto-suggest quantization if VRAM is tight ────────────────
        if device == "cuda" and not self.load_in_4bit and not self.load_in_8bit:
            self._check_vram_and_warn(total_vram_gb)

        # ── Build quantization config ─────────────────────────────────
        quant_config = None
        if self.load_in_4bit or self.load_in_8bit:
            quant_config = self._build_quant_config(torch)

        # ── Build model_kwargs ────────────────────────────────────────
        model_kwargs = {}

        if device in ("cuda", "mps"):
            model_kwargs["torch_dtype"] = torch.float16
        elif device == "cpu":
            model_kwargs["torch_dtype"] = torch.float32

        if quant_config:
            # bitsandbytes requires device_map=auto (manages placement itself)
            model_kwargs["quantization_config"] = quant_config
            model_kwargs["device_map"]          = "auto"
        elif device == "cuda":
            if n_gpus > 1:
                model_kwargs["device_map"] = "auto"   # spread across all GPUs
                logger.info(f"  Multi-GPU: using device_map=auto across {n_gpus} GPUs")
            else:
                model_kwargs["device_map"] = "auto"

        if self.hf_cache_dir:
            model_kwargs["cache_dir"] = self.hf_cache_dir

        # ── Determine pipeline device arg ─────────────────────────────
        # When device_map=auto or quantization is used, the pipeline must
        # NOT receive a device= argument — accelerate handles placement.
        pipe_device = None
        if not quant_config and device not in ("cuda",):
            pipe_device = device   # "mps" or "cpu"

        logger.info(f"  model_kwargs: {list(model_kwargs.keys())}")

        if self.trust_remote_code:
            logger.warning(
                f"  ⚠  trust_remote_code=True — executing custom Python code "
                f"shipped in the '{self.model}' HF repo. Only enable this for "
                f"models you trust."
            )

        try:
            pipe = pipeline(
                "text-generation",
                model        = self.model,
                model_kwargs = model_kwargs,
                token        = self.api_key or None,
                device       = pipe_device,
                trust_remote_code = self.trust_remote_code,
            )
            # Log actual memory used after loading
            if device == "cuda":
                used  = torch.cuda.memory_allocated()  / (1024**3)
                total = torch.cuda.get_device_properties(0).total_memory / (1024**3)
                logger.info(f"  VRAM used: {used:.1f} GB / {total:.1f} GB")
            logger.info(f"  Model ready on {device.upper()}")
            return pipe

        except Exception as e:
            raise self._build_load_error(str(e), device)

    def _detect_device(self, torch) -> tuple:
        """Returns (device_str, n_gpus, total_vram_gb)."""
        if self.device:
            device = self.device
            if device == "cuda" and torch.cuda.is_available():
                n    = torch.cuda.device_count()
                vram = sum(
                    torch.cuda.get_device_properties(i).total_memory
                    for i in range(n)
                ) / (1024**3)
                gpu_names = [torch.cuda.get_device_name(i) for i in range(n)]
                logger.info(f"  Device forced: cuda ({n} GPU(s): {', '.join(gpu_names)}, {vram:.1f} GB total VRAM)")
                return "cuda", n, vram
            logger.info(f"  Device forced: {device}")
            return device, 0, 0.0

        if torch.cuda.is_available():
            n    = torch.cuda.device_count()
            vram = sum(
                torch.cuda.get_device_properties(i).total_memory
                for i in range(n)
            ) / (1024**3)
            for i in range(n):
                props = torch.cuda.get_device_properties(i)
                g     = props.total_memory / (1024**3)
                logger.info(f"  GPU {i}: {props.name} — {g:.1f} GB VRAM")
            logger.info(f"  Total VRAM: {vram:.1f} GB across {n} GPU(s)")
            return "cuda", n, vram

        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            logger.info("  Device: Apple Silicon MPS")
            return "mps", 0, 0.0

        logger.info("  Device: CPU (no GPU detected)")
        return "cpu", 0, 0.0

    def _check_vram_and_warn(self, total_vram_gb: float):
        """Warn if the model likely won't fit in available VRAM without quantization."""
        FP16_GB = {
            "phi":      4,  "phi-3.5": 4,  "phi-4": 8,
            "7b": 14, "8b": 16, "9b": 18,
            "13b": 26, "14b": 28,
            "34b": 68, "70b": 140, "72b": 144,
        }
        model_lower = self.model.lower()
        needed = 16  # conservative default
        for key, gb in sorted(FP16_GB.items(), key=lambda x: -x[1]):
            if key in model_lower:
                needed = gb
                break

        if total_vram_gb < needed * 0.9:
            logger.warning(
                f"  ⚠  Model '{self.model}' needs ~{needed} GB VRAM in FP16, "
                f"but only {total_vram_gb:.1f} GB available.\n"
                f"  → Add --quantize 4bit  (~{needed//4} GB) or "
                f"--quantize 8bit  (~{needed//2} GB)\n"
                f"  → Or run check_gpu.py for a full recommendation"
            )

    def _build_quant_config(self, torch):
        """Build bitsandbytes quantization config."""
        try:
            from transformers import BitsAndBytesConfig
            if self.load_in_4bit:
                logger.info("  Quantization: 4-bit NF4  (bitsandbytes)")
                return BitsAndBytesConfig(
                    load_in_4bit              = True,
                    bnb_4bit_compute_dtype    = torch.float16,
                    bnb_4bit_use_double_quant = True,
                    bnb_4bit_quant_type       = "nf4",
                )
            else:
                logger.info("  Quantization: 8-bit  (bitsandbytes)")
                return BitsAndBytesConfig(load_in_8bit=True)
        except ImportError:
            logger.warning(
                "  bitsandbytes not installed — quantization skipped.\n"
                "  Install: pip install bitsandbytes"
            )
            return None

    def _build_load_error(self, err: str, device: str) -> RuntimeError:
        """Return a RuntimeError with actionable hints based on the error message."""
        if "trust_remote_code" in err.lower():
            hint = (
                f"\n\n  🔓 This repo ships custom modeling code that transformers "
                f"refuses to run without explicit consent.\n"
                f"  Only proceed if you trust the publisher — this executes "
                f"arbitrary Python from https://hf.co/{self.model}\n"
                f"  Re-run with: --trust-remote-code"
            )
        elif (
            "401 client error" in err.lower()
            or "gated repo" in err.lower()
            or "unauthorized" in err.lower()
            or "you must be authenticated" in err.lower()
            or ("access to model" in err.lower() and "restricted" in err.lower())
        ):
            # NOTE: matching on a bare "401" substring is unsafe — it can
            # false-positive on unrelated text (commit hashes, sizes, line
            # numbers, ports, etc. routinely contain "401"). Match specific
            # phrasing HF's actual gated/auth errors use instead.
            hint = (
                f"\n\n  ✋ Access denied — this is a gated model.\n"
                f"  1. Accept the licence at: https://huggingface.co/{self.model}\n"
                f"  2. Create a token:         https://huggingface.co/settings/tokens\n"
                f"  3. Re-run with:            --key hf_YOUR_TOKEN"
            )
        elif "quantized with" in err.lower() and "but you are passing" in err.lower():
            hint = (
                f"\n\n  ⚙️  This model ships pre-quantized weights with their own "
                f"baked-in quantization scheme, which conflicts with "
                f"--quantize 4bit/8bit (bitsandbytes).\n"
                f"  Re-run with: --quantize none  (loads the model's native "
                f"quantization as-is, no bitsandbytes config applied)"
            )
        elif "out of memory" in err.lower() or "cuda out" in err.lower():
            hint = (
                f"\n\n  💾 Not enough GPU memory.\n"
                f"  Try one of:\n"
                f"    --quantize 4bit           (4× memory reduction, CUDA only)\n"
                f"    --quantize 8bit           (2× memory reduction, CUDA only)\n"
                f"    --device cpu              (slow but no VRAM limit)\n"
                f"    A smaller model           e.g. Phi-3.5-mini, Mistral-7B\n"
                f"  Run: python check_gpu.py    (shows which models fit your GPU)"
            )
        elif "no module named 'bitsandbytes'" in err.lower():
            hint = (
                f"\n\n  📦 bitsandbytes is required for quantization.\n"
                f"    pip install bitsandbytes\n"
                f"  Note: bitsandbytes only supports CUDA (not CPU or MPS)."
            )
        elif "not found" in err.lower() or "does not exist" in err.lower():
            hint = (
                f"\n\n  🔍 Model not found: '{self.model}'\n"
                f"  Check the model ID at: https://huggingface.co/models\n"
                f"  Run: python main.py --list-models  (curated working models)"
            )
        else:
            hint = (
                f"\n\n  Run: python check_gpu.py  (full hardware diagnostics)\n"
                f"  Or:  python main.py --list-models  (see all supported models)"
            )
        return RuntimeError(f"Failed to load '{self.model}'.{hint}\n\nOriginal error: {err}")

    # ── HuggingFace Inference API ────────────────────────────────────────────

    def _hf_api(self, system: str, user: str) -> str:
        """
        HuggingFace Inference API.

        Two modes:
          Serverless   — uses https://api-inference.huggingface.co (default)
                         Free tier has strict rate limits; HF PRO subscription
                         gives much higher limits.
          Dedicated    — set base_url= to your dedicated endpoint URL
                         No cold starts, predictable latency, pay per hour.

        Install:
            pip install huggingface_hub>=0.24
        """
        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            raise ImportError("pip install huggingface_hub>=0.24")

        client_kwargs = {}
        if self.api_key:
            client_kwargs["token"] = self.api_key
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
            logger.debug(f"  Using dedicated HF endpoint: {self.base_url}")

        client   = InferenceClient(**client_kwargs)
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]

        try:
            resp = client.chat_completion(
                messages    = messages,
                model       = self.model if not self.base_url else None,
                max_tokens  = self.max_tokens,
                temperature = max(self.temperature, 0.01),
            )
            return resp.choices[0].message.content.strip()

        except Exception as e:
            err = str(e)
            if "loading" in err.lower() or "503" in err:
                raise RuntimeError(
                    f"Model is loading on HF serverless (cold start ~30-60s). "
                    f"Retry shortly, or use --api hf_local for instant inference.\n"
                    f"Error: {e}"
                )
            if "429" in err or "rate" in err.lower():
                raise RuntimeError(
                    f"HF API rate limit hit. Options:\n"
                    f"  1. Upgrade to HuggingFace PRO (huggingface.co/pricing)\n"
                    f"  2. Deploy a dedicated endpoint (no rate limit)\n"
                    f"  3. Use --api hf_local for local inference\n"
                    f"Error: {e}"
                )
            if "401" in err or "authorization" in err.lower():
                raise RuntimeError(
                    f"HF authentication failed.\n"
                    f"  export HF_TOKEN=hf_...   (get token: huggingface.co/settings/tokens)\n"
                    f"  or pass --key hf_...\n"
                    f"Error: {e}"
                )
            raise RuntimeError(f"HF API error: {e}")

    # ── Repr ──────────────────────────────────────────────────────────────────

    def __repr__(self):
        extras = []
        if self.load_in_4bit: extras.append("4-bit")
        if self.load_in_8bit: extras.append("8-bit")
        if self.device:       extras.append(self.device)
        suffix = f" [{', '.join(extras)}]" if extras else ""
        ep = f" @ {self.base_url}" if self.base_url and self.api_type not in ("ollama",) else ""
        return f"LLMClient(type={self.api_type!r}, model={self.model!r}{suffix}{ep})"