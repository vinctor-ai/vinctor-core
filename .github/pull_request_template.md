## Summary

<!-- What does this change, and why? -->

## Testing

```
make test
make lint
make demo
```

## Checklist

- [ ] Tests added/updated and green (`make test` + `make lint` + the demo scripts)
- [ ] Fail-closed preserved (no deny/error became a permit)
- [ ] No secrets, raw keys, or grant existence leaked in deny reasons or audit
- [ ] Schema changes additive + every schema-version assertion bumped (if applicable)
- [ ] Docs / ADR updated if behavior or the contract changed
