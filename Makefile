all:
	echo >&2 "Must specify target."

test:
	tox

clean:
	rm -f .coverage
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

.PHONY: all test clean
