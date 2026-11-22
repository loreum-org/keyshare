# Contributing

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
```

CI runs those three on every pull request.

## Secrets

Do not commit private keys, seed phrases, `.env` files, keystores, or RPC URLs that contain an API key. Test fixtures must be published example keys, or values created for that test. `.gitignore` ignores `.env` and common key files.

## Security reports

Use a private GitHub security advisory. See [SECURITY.md](SECURITY.md). Do not file a public issue for a vulnerability.

## License

By contributing, you agree that your contribution is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
