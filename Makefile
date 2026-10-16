.PHONY: install scan sbom report dashboard test lint docker docker-run scan-self

PY ?= python

install:          ## Install runtime + dev dependencies
	$(PY) -m pip install -r requirements-dev.txt

scan:             ## Scan every image in images.txt into data/scans
	$(PY) -m inspector.scan

sbom:             ## Same, plus CycloneDX SBOMs in data/sbom
	$(PY) -m inspector.scan --sbom

report:           ## Markdown summary of data/scans in the terminal
	$(PY) -m inspector.report data/scans/*.json

dashboard:        ## Start the Streamlit dashboard on :8501
	$(PY) -m streamlit run app.py

test:             ## Run the test suite
	$(PY) -m pytest -q

lint:             ## Lint and format-check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

docker:           ## Build the dashboard image
	docker build -t sdp-inspector:local .

docker-run: docker  ## Run the dashboard image with your local scans mounted
	docker run --rm -p 8501:8501 -v "$(CURDIR)/data/scans:/app/data/scans:ro" sdp-inspector:local

scan-self: docker ## Scan the dashboard image itself (what CI does)
	$(PY) -m inspector.scan sdp-inspector:local --docker-socket
