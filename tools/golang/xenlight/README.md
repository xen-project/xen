# xenlight

## About

The xenlight package provides Go bindings to Xen's libxl C library via cgo.
The package is currently in an unstable "experimental" state. This means
the package is ready for initial use and evaluation, but is not yet fully
functional. Namely, only a subset of libxl's API is implemented, and
breaking changes may occur in future package versions.

Much of the package is generated using the libxl IDL. Changes to the
generated code can be made by modifying `tools/golang/xenlight/gengotypes.py`
in the xen.git tree.

## Getting Started

```go
import (
        "xenbits.xenproject.org/git-http/xen.git/tools/golang/xenlight"
)
```

The module is not yet tagged independently of xen.git; if you don’t specify
the version, you’ll get the most recent development version, which is
probably not what you want. A better option would be to specify a Xen
release tag; for instance:

    go get xenbits.xenproject.org/git-http/xen.git/tools/golang/xenlight@RELEASE-4.14.0.
