// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::io::Write as _;
use std::sync::LazyLock;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

use super::shared::*;

const ASSET_VERSION_PLACEHOLDER: &str = "__ASSET_VERSION__";

struct StaticAsset {
    name: &'static str,
    content_type: &'static str,
    body: &'static str,
}

const STATIC_ASSETS: [StaticAsset; 7] = [
    StaticAsset {
        name: "app.css",
        content_type: "text/css; charset=utf-8",
        body: include_str!("../../templates/static/app.css"),
    },
    StaticAsset {
        name: "app.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/app.js"),
    },
    StaticAsset {
        name: "login.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/login.js"),
    },
    StaticAsset {
        name: "telegram.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/telegram.js"),
    },
    StaticAsset {
        name: "steam.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/steam.js"),
    },
    StaticAsset {
        name: "settings.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/settings.js"),
    },
    StaticAsset {
        name: "admin.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../../templates/static/admin.js"),
    },
];

/// Content hash of every bundled asset. Templates reference assets with this
/// value as a query string so browsers can cache them forever.
static ASSET_VERSION: LazyLock<String> = LazyLock::new(|| {
    let mut hasher = Sha256::new();
    for asset in &STATIC_ASSETS {
        hasher.update(asset.name.as_bytes());
        hasher.update(asset.body.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
});

/// Gzip bodies are built once; assets carry no secrets, so compressing them is
/// safe (unlike reflected HTML responses).
static GZIPPED_ASSETS: LazyLock<Vec<Option<Vec<u8>>>> = LazyLock::new(|| {
    STATIC_ASSETS
        .iter()
        .map(|asset| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(asset.body.as_bytes()).ok()?;
            encoder.finish().ok()
        })
        .collect()
});

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/static/{file}", get(static_asset_handler))
}

/// Embedded templates with the asset version filled in and indentation removed
/// to keep rendered pages small.
pub(crate) fn versioned_templates() -> impl Iterator<Item = (&'static str, String)> {
    EMBEDDED_TEMPLATES.iter().map(|(name, source)| {
        (
            *name,
            compact_template(source).replace(ASSET_VERSION_PLACEHOLDER, &ASSET_VERSION),
        )
    })
}

fn compact_template(source: &str) -> String {
    let mut compact = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        compact.push_str(trimmed);
        compact.push('\n');
    }
    compact
}

async fn static_asset_handler(AxumPath(file): AxumPath<String>, headers: HeaderMap) -> Response {
    let Some(index) = STATIC_ASSETS.iter().position(|asset| asset.name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let asset = &STATIC_ASSETS[index];
    let accepts_gzip = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim().starts_with("gzip")));
    let base_headers = [
        (header::CONTENT_TYPE, asset.content_type),
        (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::VARY, "Accept-Encoding"),
    ];

    if accepts_gzip {
        if let Some(Some(gzipped)) = GZIPPED_ASSETS.get(index) {
            return (
                base_headers,
                [(header::CONTENT_ENCODING, "gzip")],
                gzipped.as_slice(),
            )
                .into_response();
        }
    }
    (base_headers, asset.body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_template_strips_indentation_and_blank_lines() {
        assert_eq!(
            compact_template("  <a>\n\n    b\n</a>  \n"),
            "<a>\nb\n</a>  \n"
        );
    }

    #[test]
    fn versioned_templates_replace_asset_placeholder() {
        let rendered = versioned_templates()
            .find(|(name, _)| *name == "base.html")
            .map(|(_, source)| source)
            .expect("base template should exist");
        assert!(!rendered.contains(ASSET_VERSION_PLACEHOLDER));
        assert!(rendered.contains(&format!("/static/app.css?v={}", *ASSET_VERSION)));
    }
}
