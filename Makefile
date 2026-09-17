.PHONY: validate test policy-test

validate: test
	python scripts/validate_layout.py

test:
	python -m unittest discover -s tests

policy-test:
	opa test policies/opa -v
	python scripts/test_admission.py
