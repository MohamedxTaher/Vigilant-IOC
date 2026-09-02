.PHONY: lint test run

lint:
	ruff check .
	mypy vigilant_ioc_core main.py logger.py settings.py

test:
	pytest -v --cov=vigilant_ioc_core

run:
	python main.py $(ARGS)
