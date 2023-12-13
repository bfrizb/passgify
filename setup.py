#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

__version__ = '0.2.16'

setup(
    name="passgify",
    version=__version__,
    author="Brian Frisbie",
    author_email="bfrizb@github.com",
    description="A tool to deterministically generate pseudo-random passwords",
    url="https://github.com/bfrizb/passgify",
    scripts=["src/pgen.py"],
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "pyperclip",
        "pyyaml",
        'importlib-metadata >= 1.0 ; python_version < "3.8"'
    ],
)
