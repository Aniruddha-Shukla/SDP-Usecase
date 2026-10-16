# syntax=docker/dockerfile:1
# The dashboard image. CI scans this image with Trivy and fails on fixable CRITICALs.

# Base pinned by digest so builds are reproducible; Dependabot bumps it (see .github/dependabot.yml).
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app .streamlit/ .streamlit/
COPY --chown=app:app inspector/ inspector/
COPY --chown=app:app app.py ./
# Bundled sample reports so the container shows something on first run.
# Mount real scans over /app/data/scans:  docker run -v "$PWD/data/scans:/app/data/scans:ro" ...
COPY --chown=app:app data/sample/ data/sample/

USER app
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
