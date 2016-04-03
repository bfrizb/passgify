[![Build Status](https://travis-ci.org/bfrizb/passgify.svg?branch=master)](https://travis-ci.org/bfrizb/passgify)

Passgify
====================================================

A tool to deterministically generate pseudo-random passwords. (Passgify is pronounced like "pacify", but with a 'g' instead of a 'c' sound)

Run Instructions
----------------

* Download repo
* `cd passgify`
* (On OSX) `sudo easy_install pip && sudo pip install -r requirements.txt`
* `python src/pgen.py -h`

Dev Instructions
----------------

Following the same instructions as the **Run Instructions** above. After making changes, run your tests with:
* `make test`
