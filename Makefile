test:
	black *.py
	tox

clean:
	rm -rf .cache .coverage .tox build dist *.egg-info
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

.PHONY: test clean
