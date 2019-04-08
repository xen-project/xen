#!/bin/bash

# For a newly pushed branch the BEFORE_SHA will be all 0s
if [[ ${CI_COMMIT_BEFORE_SHA} == 0000000000000000000000000000000000000000 ]]; then
    echo "Newly pushed branch, skipped"
    exit 0
fi

git merge-base --is-ancestor ${CI_COMMIT_BEFORE_SHA} ${CI_COMMIT_SHA}
if [[ $? -ne 0 ]]; then
    echo "${CI_COMMIT_SHA} is not a descendent of ${CI_COMMIT_BEFORE_SHA}, skipped"
    exit 0
fi

echo "Building ${CI_COMMIT_BEFORE_SHA}..${CI_COMMIT_SHA}"

NON_SYMBOLIC_REF=1 ./automation/scripts/build-test.sh ${CI_COMMIT_BEFORE_SHA} ${CI_COMMIT_SHA} \
    bash -c "make -j4 distclean && ./automation/scripts/build"
