.PHONY: validate test

validate: test
	python scripts/validate_layout.py

test:
	python -m unittest discover -s tests
