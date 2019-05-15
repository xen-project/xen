#!/bin/bash

# For a newly pushed branch the BEFORE_SHA will be all 0s
if [[ ${BASE} == 0000000000000000000000000000000000000000 ]]; then
    echo "Newly pushed branch, skipped"
    exit 0
fi

git merge-base --is-ancestor ${BASE} ${TIP}
if [[ $? -ne 0 ]]; then
    echo "${TIP} is not a descendent of ${BASE}, skipped"
    exit 0
fi

echo "Building ${BASE}..${TIP}"

NON_SYMBOLIC_REF=1 ./automation/scripts/build-test.sh ${BASE} ${TIP} \
    bash -c "git clean -ffdx && ./automation/scripts/build"
