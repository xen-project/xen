#   Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

## XEND_DOMAIN_CREATE = "xend.domain.create": dom
## create: 
## xend.domain.destroy: dom, reason:died/crashed
## xend.domain.up ?

## xend.domain.unpause: dom
## xend.domain.pause: dom
## xend.domain.shutdown: dom
## xend.domain.halt: dom

## xend.domain.migrate.begin: dom, to
## Begin tells: src host, src domain uri, dst host. Dst id known?
## err: src host, src domain uri, dst host, dst id if known, status (of domain: ok, dead,...), reason
## end: src host, src domain uri, dst host, dst uri

## Events for both ends of migrate: for exporter and importer?
## Include migrate id so can tie together.
## Have uri /xend/migrate/<id> for migrate info (migrations in progress).

## (xend.domain.migrate.begin (src <host>) (src.domain <id>)
##                            (dst <host>) (id <migrate id>))
 
## xend.domain.migrate.end:
## (xend.domain.migrate.end (domain <id>) (to <host>)

## xend.node.up:  xend uri
## xend.node.down: xend uri

## xend.error ?

## format:

