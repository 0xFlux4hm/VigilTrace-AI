PY ?= python3

.PHONY: install test server-smoke build-extension docs ingest smoke doctor zip clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest tests/ -q

server-smoke:
	$(PY) -m aobh.tools.server --list-tools | wc -l

build-extension:
	$(PY) extension/build.py --test --jdk $(JDK) --api-jar $(API_JAR) --test-java $(JAVA)

docs:
	$(PY) scripts/gen_docs.py

ingest:
	$(PY) scripts/ingest.py

smoke:
	$(PY) scripts/smoke.py

doctor:
	$(PY) -m aobh.tools.cli doctor

zip:
	cd .. && zip -rq aobh-1.0.0.zip aobh -x "aobh/extension/build/*" "aobh/extension/.deps/*" "aobh/extension/target/*" "aobh/**/__pycache__/*" "aobh/.pytest_cache/*" "aobh/*.egg-info/*" "aobh/.git/*" && ls -la aobh-1.0.0.zip

clean:
	rm -rf build dist *.egg-info .pytest_cache extension/build extension/.deps extension/target
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
