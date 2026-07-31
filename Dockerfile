# Sentinel — Hugging Face Space (Docker SDK), full V2, CPU-only.
#
# HF Spaces runs this image and routes traffic to $app_port (7860). The semantic
# tiers need an embedding model (MiniLM); torch is installed from the CPU wheel
# index so the image is ~1GB, not ~4GB, and MiniLM is baked in at build time so
# the first request doesn't pay a download.
FROM python:3.12-slim

# No system build deps needed: torch (CPU), numpy and sentence-transformers all
# install from prebuilt manylinux wheels on this base image.

# HF Spaces convention: run as a non-root user with a writable home.
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    HF_HOME=/home/user/.cache/huggingface \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /home/user/app

# --- python deps -----------------------------------------------------------
# CPU-only torch first (small), then the rest.
COPY --chown=user requirements-deploy.txt .
RUN pip install --no-cache-dir --user \
        torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir --user -r requirements-deploy.txt

# --- app -------------------------------------------------------------------
COPY --chown=user app/       app/
COPY --chown=user policies/  policies/
COPY --chown=user models/    models/

# Bake the embedding model into the image so boot has no network dependency.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# Bake the Stage-8 DeBERTa injection classifier too (ML_DETECTOR_ENABLED=true).
# ~750MB; downloading it on first request would make cold starts unusable, so it
# ships in the image. Must match settings.ML_MODEL_NAME.
RUN python -c "from transformers import pipeline; \
    pipeline('text-classification', \
             model='protectai/deberta-v3-base-prompt-injection-v2', \
             top_k=None)"

# --- runtime config --------------------------------------------------------
# Full V2 semantic + behavioural stack on, including the DeBERTa recheck (needs
# an upgraded/always-on Space — ~340ms/prompt on CPU). Audit DB to /tmp.
ENV KNN_ENABLED=true \
    INTENT_ML_ENABLED=true \
    BEHAVIOUR_ENABLED=true \
    ML_DETECTOR_ENABLED=true \
    DB_URL=sqlite:////tmp/sentinel_audit.db \
    PORT=7860

EXPOSE 7860
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
