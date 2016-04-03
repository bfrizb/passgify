#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


setup(
    name="passgify",
    version=0.1,
    author="Brian Frisbie",
    description="A tool to deterministically generate pseudo-random passwords",
    packages=find_packages(exclude=["tests"]),
)
