"""
check_gpu.py
============
Run this FIRST on your GPU machine to check readiness before evaluating skills.

  python check_gpu.py

Tells you:
  - What GPU(s) you have and how much VRAM
  - Whether CUDA / MPS / ROCm is available
  - Which models fit in your available VRAM
  - Exact install command for your setup
  - Whether quantization is needed
"""

import sys
import platform
import subprocess

def hr(char="─", w=68): print(char * w)

def gb(n_bytes): return n_bytes / (1024**3)

def check():
    hr("═")
    print("  GPU READINESS CHECK — Skill Security Evaluator")
    hr("═")

    py = sys.version.split()[0]
    print(f"\n  Python  : {py}")
    print(f"  OS      : {platform.system()} {platform.machine()}")

    # ── PyTorch ──────────────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [1] PyTorch")
    hr()
    try:
        import torch
        print(f"  ✅ PyTorch {torch.__version__}")
    except ImportError:
        print("  ❌ PyTorch not installed")
        print("     → Run the install command shown at the bottom")
        torch = None

    # ── CUDA (NVIDIA) ─────────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [2] NVIDIA CUDA")
    hr()
    nvidia_ok  = False
    total_vram = 0
    gpus       = []

    if torch and torch.cuda.is_available():
        n = torch.cuda.device_count()
        print(f"  ✅ CUDA available — {n} GPU(s) found")
        for i in range(n):
            props    = torch.cuda.get_device_properties(i)
            vram_gb  = gb(props.total_memory)
            total_vram += vram_gb
            gpus.append((props.name, vram_gb))
            print(f"     GPU {i}: {props.name}")
            print(f"            VRAM  : {vram_gb:.1f} GB")
            print(f"            Compute: {props.major}.{props.minor}")
        print(f"\n     Total VRAM: {total_vram:.1f} GB")
        nvidia_ok = True

        # CUDA version
        try:
            v = subprocess.check_output(["nvcc","--version"], text=True)
            cv = [l for l in v.split("\n") if "release" in l]
            if cv: print(f"     CUDA toolkit: {cv[0].strip()}")
        except Exception:
            pass
        print(f"     PyTorch CUDA build: {torch.version.cuda}")

    else:
        if torch:
            print("  ❌ CUDA not available")
            # Check if nvidia-smi exists but CUDA not in torch
            try:
                smi = subprocess.check_output(["nvidia-smi","--query-gpu=name,memory.total",
                                               "--format=csv,noheader"], text=True).strip()
                print(f"     nvidia-smi found GPU(s):\n       {smi}")
                print("     → PyTorch was built WITHOUT CUDA — reinstall with CUDA support")
            except Exception:
                print("     → No NVIDIA GPU detected")
        else:
            print("  ⚠  (PyTorch not installed — cannot check)")

    # ── Apple Silicon MPS ─────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [3] Apple Silicon MPS")
    hr()
    mps_ok = False
    if torch and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        print("  ✅ MPS available (Apple Silicon GPU)")
        mps_ok = True
        try:
            import subprocess
            result = subprocess.check_output(
                ["system_profiler","SPDisplaysDataType"], text=True
            )
            for line in result.split("\n"):
                if "Chipset" in line or "VRAM" in line or "Metal" in line:
                    print(f"     {line.strip()}")
        except Exception:
            pass
    else:
        print("  —  Not applicable (not Apple Silicon)")

    # ── AMD ROCm ─────────────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [4] AMD ROCm")
    hr()
    if torch and hasattr(torch.version, "hip") and torch.version.hip:
        print(f"  ✅ ROCm available: {torch.version.hip}")
        print(f"     AMD GPU support confirmed")
    else:
        print("  —  ROCm not detected")

    # ── Key packages ─────────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [5] Required packages")
    hr()
    packages = {
        "transformers":    "HuggingFace model loading",
        "accelerate":      "Multi-GPU / device_map=auto",
        "huggingface_hub": "Model download + HF API",
        "bitsandbytes":    "4-bit / 8-bit quantization (CUDA only)",
        "anthropic":       "Anthropic Claude API",
        "rich":            "Colored terminal output",
    }
    missing = []
    for pkg, desc in packages.items():
        try:
            mod = __import__(pkg.replace("-","_"))
            ver = getattr(mod, "__version__", "?")
            print(f"  ✅ {pkg:<20s} {ver:<12s} {desc}")
        except ImportError:
            print(f"  ❌ {pkg:<20s} {'MISSING':<12s} {desc}")
            missing.append(pkg)

    # ── Model fit guide ───────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [6] Model sizing guide for your hardware")
    hr()

    MODELS = [
        ("microsoft/Phi-3.5-mini-instruct",          3.8,  1.2,  "Tiny, CPU-friendly"),
        ("mistralai/Mistral-7B-Instruct-v0.3",        14.5, 4.5,  "Fast, good JSON"),
        ("meta-llama/Meta-Llama-3.1-8B-Instruct",    16.0, 5.0,  "Best 8B for instructions"),
        ("Qwen/Qwen2.5-7B-Instruct",                 14.0, 4.5,  "Great JSON output"),
        ("Qwen/Qwen2.5-14B-Instruct",                28.0, 8.5,  "Strong security reasoning"),
        ("mistralai/Mixtral-8x7B-Instruct-v0.1",     48.0, 14.0, "Strong MoE reasoning"),
        ("meta-llama/Meta-Llama-3.1-70B-Instruct",  140.0, 40.0, "Best open-source quality"),
    ]

    avail_vram = total_vram if nvidia_ok else (0 if not mps_ok else 16.0)

    print(f"  Available VRAM: {avail_vram:.1f} GB\n")
    print(f"  {'Model':<52} {'FP16':>7} {'4-bit':>7}  {'Fits?':<22} Notes")
    print(f"  {'-'*52} {'-'*7} {'-'*7}  {'-'*22} {'-'*20}")

    for name, fp16, q4, note in MODELS:
        if avail_vram == 0:
            fits = "CPU only (slow)"
        elif avail_vram >= fp16:
            fits = "✅ fits in FP16"
        elif avail_vram >= q4:
            fits = "✅ fits with --quantize 4bit"
        else:
            fits = "❌ too large"
        short = name.split("/")[-1]
        print(f"  {short:<52} {fp16:>5.0f}GB {q4:>5.0f}GB  {fits:<26} {note}")

    # ── Recommendation ────────────────────────────────────────────────
    print("\n" + "─"*68)
    print("  [7] Recommended command for your hardware")
    hr()

    if nvidia_ok and total_vram >= 16:
        rec_model = "meta-llama/Meta-Llama-3.1-8B-Instruct"
        rec_flags = "--api hf_local --device cuda"
        if total_vram >= 48:
            rec_model = "mistralai/Mixtral-8x7B-Instruct-v0.1"
        elif total_vram >= 28:
            rec_model = "Qwen/Qwen2.5-14B-Instruct"
        print(f"  Your GPU has {total_vram:.0f} GB VRAM — recommended setup:\n")
        print(f"    python main.py skills/ {rec_flags} --model {rec_model}")
    elif nvidia_ok and total_vram >= 5:
        rec_model = "mistralai/Mistral-7B-Instruct-v0.3"
        print(f"  Your GPU has {total_vram:.0f} GB VRAM — use 4-bit quantization:\n")
        print(f"    python main.py skills/ --api hf_local --device cuda --quantize 4bit \\")
        print(f"      --model {rec_model}")
    elif mps_ok:
        print("  Apple Silicon MPS detected:\n")
        print("    python main.py skills/ --api hf_local --device mps \\")
        print("      --model Qwen/Qwen2.5-7B-Instruct")
    else:
        print("  No GPU detected — running on CPU (slow for 7B+ models).\n")
        print("  Fastest CPU option:")
        print("    python main.py skills/ --api hf_local --device cpu \\")
        print("      --model microsoft/Phi-3.5-mini-instruct")
        print("\n  Or use a cloud API instead (no GPU needed):")
        print("    python main.py skills/ --api anthropic    # Claude")
        print("    python main.py skills/ --api hf_api --key hf_...  # HF hosted")

    # ── Install command ───────────────────────────────────────────────
    if missing or not torch or (torch and not torch.cuda.is_available() and not mps_ok):
        print("\n" + "─"*68)
        print("  [8] Install command")
        hr()

        if not torch or (torch and not torch.cuda.is_available()):
            # Detect CUDA version from system
            cuda_ver = "cu121"   # safe default
            try:
                out = subprocess.check_output(["nvidia-smi"], text=True)
                for line in out.split("\n"):
                    if "CUDA Version" in line:
                        v = line.split("CUDA Version:")[-1].strip().split()[0]
                        major, minor = v.split(".")[:2]
                        cuda_ver = f"cu{major}{minor}"
                        break
            except Exception:
                pass

            if platform.system() == "Darwin":
                print("\n  macOS (Apple Silicon):")
                print("    pip install torch torchvision torchaudio")
            else:
                print(f"\n  Linux/Windows with NVIDIA GPU (detected CUDA {cuda_ver}):")
                print(f"    pip install torch torchvision torchaudio \\")
                print(f"      --index-url https://download.pytorch.org/whl/{cuda_ver}")

        if missing:
            pkgs = " ".join(p for p in missing if p != "bitsandbytes")
            print(f"\n  Core packages:")
            print(f"    pip install {pkgs}")
            if "bitsandbytes" in missing and nvidia_ok:
                print(f"\n  For quantization (CUDA only):")
                print(f"    pip install bitsandbytes")

    hr("═")
    print("  Done. Run with --list-models to see all available models.")
    hr("═")
    print()

if __name__ == "__main__":
    check()