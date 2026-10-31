<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Contributing to Hanagram-web

Thanks for your interest! Bug reports, feature ideas, translations and pull requests are all welcome.

## Reporting issues

- Search existing issues first.
- Include the version (image tag or commit), how you run it (Docker / source), steps to reproduce, and relevant log lines.
- **Never paste session strings, maFiles, passwords, tokens or other secrets.** Redact them.

## Security vulnerabilities

Please do not open a public issue. Report it privately through GitHub's **Report a vulnerability** button on the repository's Security tab.

## Development setup

Requires Rust 1.85.1 or newer.

```bash
git clone https://github.com/XMZO/Hanagram-web.git && cd Hanagram-web
cp .env.example .env
cargo run            # serves http://localhost:8080
cargo test
```

- Templates and static assets live in `templates/` and are compiled into the binary.
- UI text lives in `src/i18n/en.rs` and `src/i18n/zh_cn.rs`. When you add or change a string, update both.

## Pull requests

- Keep each PR focused on one change, and explain what it does and why.
- Run `cargo fmt` and `cargo test` before you submit.
- Match the style of the surrounding code. New source files start with the same SPDX license header as existing ones.
- If behavior or setup changes, update both `README.md` and `README.zh-CN.md`.

## License

By contributing, you agree that your contributions are licensed under the [AGPL-3.0-or-later](LICENSE).
