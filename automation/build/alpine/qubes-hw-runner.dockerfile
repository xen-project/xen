# syntax=docker/dockerfile:1
FROM --platform=linux/arm64/v8 alpine:3.24
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

RUN apk --no-cache add bash

RUN <<EOF
#!/bin/bash
    set -eu

    DEPS=(
          expect
          openssh-client
    )

    apk add --no-cache "${DEPS[@]}"
EOF

USER root
WORKDIR /build
