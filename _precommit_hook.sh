#!/bin/bash

current_minor_version=0.2
num_revs=$(git rev-list --count HEAD)
revs_at_last_minor_version=14
let build_number=${num_revs}-${revs_at_last_minor_version}

if ! grep -q "__version__ = '"${current_minor_version}.${build_number} setup.py; then
    sed -i "" "s/__version__ =.*/__version__ = '"${current_minor_version}.${build_number}"'/" setup.py
    echo
    echo '*ABORTING* "git commit" and updating __version__ in setup.py to what is expected'
    git add setup.py
    git status
    exit -1
fi
