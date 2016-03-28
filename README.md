[![Build Status](https://travis-ci.org/bfrizb/yad-pac.svg?branch=master)](https://travis-ci.org/bfrizb/yad-pac)

Yet Another Deterministic Password Creator (yad-pac)
====================================================

A tool to deterministically generate pseudo-random passwords.

Run Instructions
----------------

* Download repo
* `cd yad-pac`
* (On OSX) `sudo easy_install pip && sudo pip install -r requirements.txt`
* `python src/pgen.py -h`

Dev Instructions
----------------

Following the same instructions as the **Run Instructions** above. After making changes, run your tests with:
* `make test`
