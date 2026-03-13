// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::shared::*;
use super::{
    admin, auth, dashboard, maintenance, middleware as web_middleware, notifications, sessions,
};

fn load_embedded_templates() -> Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_templates(EMBEDDED_TEMPLATES)
        .context("failed to initialize embedded templates")?;
    Ok(tera)
}

pub(crate) async fn run() -> Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("healthcheck")) {
        return run_healthcheck_command().await;
    }

    dotenvy::dotenv().ok();
    init_tracing();
    harden_process_memory();

    let config = load_config()?;
    let runtime = RuntimeConfig {
        sessions_dir: config.sessions_dir.clone(),
        users_dir: config.sessions_dir.join("users"),
        app_data_dir: config.sessions_dir.join(".hanagram"),
        runtime_cache_dir: config.sessions_dir.join(".hanagram").join("runtime-cache"),
        meta_db_path: config
            .sessions_dir
            .join(".hanagram")
            .join(META_DB_FILE_NAME),
    };

    tokio::fs::create_dir_all(&runtime.sessions_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.sessions_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.users_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.users_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.app_data_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.app_data_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.runtime_cache_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.runtime_cache_dir.display()))?;

    let tera = Arc::new(load_embedded_templates()?);
    let shared_state: SharedState = Arc::new(RwLock::new(HashMap::new()));
    let session_workers: SessionWorkers = Arc::new(Mutex::new(HashMap::new()));
    let phone_flows: PendingPhoneFlows = Arc::new(RwLock::new(HashMap::new()));
    let qr_flows: PendingQrFlows = Arc::new(RwLock::new(HashMap::new()));
    let totp_setups: PendingTotpSetups = Arc::new(RwLock::new(HashMap::new()));
    let passkey_registrations: PendingPasskeyRegistrations = Arc::new(RwLock::new(HashMap::new()));
    let passkey_authentications: PendingPasskeyAuthentications =
        Arc::new(RwLock::new(HashMap::new()));
    let recovery_notices: PendingRecoveryNotices = Arc::new(RwLock::new(HashMap::new()));
    let unlock_cache: UnlockCache = Arc::new(RwLock::new(HashMap::new()));
    let user_keys: UserKeyCache = Arc::new(RwLock::new(HashMap::new()));
    let meta_store = Arc::new(MetaStore::open(&runtime.meta_db_path).await?);
    let system_settings = Arc::new(RwLock::new(meta_store.load_system_settings().await?));
    let runtime_cache = Arc::new(RuntimeCache::open(runtime.runtime_cache_dir.clone()).await?);

    let app_state = AppState {
        shared_state: Arc::clone(&shared_state),
        session_workers,
        runtime_cache,
        tera,
        meta_store: Arc::clone(&meta_store),
        system_settings,
        runtime,
        phone_flows,
        qr_flows,
        totp_setups,
        passkey_registrations,
        passkey_authentications,
        recovery_notices,
        unlock_cache,
        user_keys,
        http_client: HttpClient::new(),
    };

    maintenance::run_startup_maintenance(&app_state).await?;

    let session_records = app_state.meta_store.list_all_session_records().await?;
    for session_record in session_records {
        sessions::register_session_record(&app_state, session_record).await;
    }

    maintenance::spawn_background_maintenance(app_state.clone());

    let protected = Router::new()
        .merge(dashboard::routes())
        .merge(auth::protected_routes())
        .merge(notifications::routes())
        .merge(admin::routes())
        .merge(sessions::routes())
        .route_layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            web_middleware::require_login,
        ));

    let app = Router::new()
        .merge(protected)
        .merge(auth::public_routes())
        .route("/health", get(health_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    info!("listening on http://{}", config.bind_addr);
    axum::serve(listener, app)
        .await
        .context("axum server exited unexpectedly")
}

async fn run_healthcheck_command() -> Result<()> {
    let url = std::env::args()
        .nth(2)
        .unwrap_or_else(|| String::from("http://127.0.0.1:8080/health"));
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("healthcheck request failed for {url}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "healthcheck returned {}",
        response.status()
    );
    Ok(())
}

fn init_tracing() {
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

fn harden_process_memory() {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                warn!(
                    "failed disabling core dumps: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                warn!(
                    "failed disabling process dumpability: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

fn load_config() -> Result<Config> {
    let sessions_dir = std::env::var("SESSIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sessions"));

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| String::from("0.0.0.0:8080"))
        .parse::<SocketAddr>()
        .context("BIND_ADDR must be a valid socket address")?;

    Ok(Config {
        sessions_dir,
        bind_addr,
    })
}

async fn health_handler(State(app_state): State<AppState>) -> Json<HealthResponse> {
    let sessions = app_state.shared_state.read().await.len();
    Json(HealthResponse {
        status: "ok",
        sessions,
    })
}
