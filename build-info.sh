#!/bin/bash

if [ -f .git/HEAD ]; then
    GIT_COMMIT=$(cut -c -7 ".git/$(sed 's/^ref: //' .git/HEAD)")
    printf "#define GIT_COMMIT \"%s\"\n" "$GIT_COMMIT" > $1
else
    touch $1
fi
