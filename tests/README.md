# Tests

Two suites. Neither needs cloud access and neither touches host networking.

## Parser

```
bash tests/test-parser.sh
```

Runs `analysis/extract_php2shell.py` over `samples/raw` and checks the
verdicts: a benign request is not reported, legitimate
`session.upload_progress` traffic stays low, the signature shape scores
"likely", and the two-request pattern is paired by session id.

The samples are inert. They reproduce the string shape of the published
chain and contain no exploit.

## Gateway

```
docker build -t hp-nftcheck tests/
docker run --rm --net=none --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "$PWD":/w -w /w hp-nftcheck bash /w/tests/test-gateway.sh
```

`--net=none` gives the container its own empty network namespace, so
`flush ruleset` and the real rule load affect only that namespace.

It covers: the ruleset renders and loads; input and forward default to drop;
mail and private-space egress are dropped; the egress chain ends in an
explicit drop with no fallthrough; the watchdog's counter query parses; the
watchdog does not fire at exactly the limit, does fire one byte over, and
ignores a counter reset; the kill switch inserts rules above the accept rules
in both directions; re-arm removes them cleanly; shellcheck is clean.

The watchdog reads its counter through `HP_COUNTER_CMD` when that is set,
which is how the arithmetic is tested without generating traffic. It is
unset in production.
