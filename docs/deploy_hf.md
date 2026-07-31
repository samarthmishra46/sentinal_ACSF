# Deploying Sentinel to Hugging Face Spaces

The full V2 stack (rules + kNN + intent classifier + behaviour) runs on a **free
HF Docker Space**. HF's free tier has 16 GB RAM, so torch + the MiniLM embedder
fit comfortably — the thing that made Render's 512 MB free tier impossible.

## What ships

- `Dockerfile` — CPU-only torch, bakes MiniLM into the image, serves on port 7860.
- `requirements-deploy.txt` — runtime deps only (no sklearn; that's training-only,
  the intent classifier runs as pure numpy over `models/intent_clf.json`).
- `.dockerignore` — keeps `.venv`, tests, synthetic data out of the image.
- `README.md` — carries the HF Space YAML header (`sdk: docker`, `app_port: 7860`).
- `models/attack_bank.{npz,json}` + `models/intent_clf.json` — committed, so they
  ship in the image. All well under HF's 10 MB inline limit; no git-lfs needed.

## Steps

1. **Create the Space** at <https://huggingface.co/new-space>:
   - Space name: `sentinel` → URL becomes `https://<username>-sentinel.hf.space`
   - SDK: **Docker** → **Blank**
   - Hardware: **CPU upgrade** (recommended — DeBERTa on `CPU basic` free
     tier cold-starts slowly and adds ~340ms/prompt; a Pro subscription can
     run the upgraded/always-on tier)

2. **Add the Space as a git remote** and push this branch to its `main`:
   ```bash
   git remote add hf https://huggingface.co/spaces/<username>/sentinel
   git push hf samarth-new:main
   ```
   When prompted, the **password is an HF write token**
   (<https://huggingface.co/settings/tokens>), not your account password.

3. **Watch the build** on the Space page. First build is ~8–12 min (installs torch,
   bakes MiniLM **and the ~750MB DeBERTa classifier**). When it goes green:
   - `https://<username>-sentinel.hf.space/` — web UI
   - `https://<username>-sentinel.hf.space/health` — should report `rules+knn+intent+ml`
   - `https://<username>-sentinel.hf.space/v1/chat` — the API

## Runtime config (set in the Dockerfile, override in Space "Settings → Variables")

| Var | Value | Meaning |
|-----|-------|---------|
| `KNN_ENABLED` | `true` | similarity vs attack bank |
| `INTENT_ML_ENABLED` | `true` | compliance-intent classifier |
| `BEHAVIOUR_ENABLED` | `true` | session-level anomaly |
| `ML_DETECTOR_ENABLED` | `true` | DeBERTa recheck — baked into image; needs an upgraded/always-on Space (~340ms/prompt on CPU) |
| `DB_URL` | `sqlite:////tmp/sentinel_audit.db` | ephemeral audit log |

## Honest limits

- **Demo, not SLA.** Free Spaces sleep after ~48 h idle and cold-start (~30–60 s
  while the embedder loads) on the next request. HF "CPU upgrade" (~$0.03/hr)
  removes the sleep for an always-on version.
- **Ephemeral storage** — the SQLite audit DB resets on restart. Fine for a demo;
  models and the attack bank live in the image.
- **Public URL + stub identity** — the EIM auth layer is a stub, so use the demo
  personas only. Do not submit real customer data.

## Lighter always-on alternative

For a small always-on box elsewhere, swap the embedder from torch to
`fastembed`/onnxruntime (~250 MB instead of ~1 GB) behind the one function in
`app/pdp/knn/embed.py`. The intent classifier is already torch-free.
