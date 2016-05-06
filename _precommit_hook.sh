#!/bin/bash

current_minor_version=0.2
num_revs=$(git rev-list --count HEAD)
revs_at_last_minor_version=14
let build_number=${num_revs}-${revs_at_last_minor_version}

sed -i "" "s/__version__ =.*/__version__ = '"${current_minor_version}.${build_number}"'/" setup.py
