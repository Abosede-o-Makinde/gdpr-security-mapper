.PHONY: install dev lint test scan sample dashboard help

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check gdpr_mapper/ tests/
	ruff format --check gdpr_mapper/ tests/

format:
	ruff format gdpr_mapper/ tests/

test:
	pytest

test-cov:
	pytest --cov=gdpr_mapper --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

scan:
	gdpr-mapper scan data/sample_configs/sample_compliant.yaml

scan-gaps:
	gdpr-mapper scan data/sample_configs/sample_gaps.yaml --report console

scan-pdf:
	gdpr-mapper scan data/sample_configs/sample_partial.yaml --report pdf --output report.pdf

sample:
	gdpr-mapper sample --output my_system.yaml
	@echo "Edit my_system.yaml then run: make scan"

dashboard:
	gdpr-mapper serve

help:
	@echo "gdpr-security-mapper — available targets:"
	@echo "  install     Install package"
	@echo "  dev         Install with dev dependencies"
	@echo "  lint        Run ruff linter"
	@echo "  format      Auto-format with ruff"
	@echo "  test        Run test suite"
	@echo "  test-cov    Run tests with HTML coverage report"
	@echo "  scan        Scan sample compliant config (console output)"
	@echo "  scan-gaps   Scan sample gap config (console output)"
	@echo "  scan-pdf    Scan sample partial config → PDF report"
	@echo "  sample      Generate a blank config template"
	@echo "  dashboard   Launch Streamlit web dashboard"
