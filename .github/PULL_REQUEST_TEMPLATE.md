## Summary

Describe what changed and why.

## Validation

- [ ] `go test -race -shuffle=on ./...`
- [ ] `go vet ./...`
- [ ] `go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...`
- [ ] Documentation and examples are updated where behavior changed.
- [ ] No secrets, packet captures, generated binaries, or coverage files are committed.

## Security and compatibility

Describe any privilege, network, configuration, data-format, or platform impact.
