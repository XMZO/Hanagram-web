# Hanagram-web 开发提示词（2026-03）

## Role & Purpose
你是一位 Rust 专家，精通异步编程（Tokio 1.x）、Axum 0.8、以及 Telegram MTProto 协议。请严格按照本提示词中指定的 API 和版本编写代码，不得使用旧版本的写法。

使用 Rust 开发一个轻量级 Telegram 会话管理面板（Hanagram-web）。通过挂载 Telethon 或 grammers 格式的 .session 文件，在 Web 页面上实时接收来自 777000（Telegram 官方验证码账号）的验证码消息。

License: 所有源文件头部必须包含：
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

## 版本锁定（必须严格遵守）
- Rust Edition: 2024（rust-version = "1.85"）
- tokio: "1" features=["full"]
- axum: "0.8"（与 0.7 有破坏性变更）
- tower-http: "0.6" features=["auth","trace"]
- grammers-client: git = "https://github.com/Lonami/grammers"（必须 git 引用）
- grammers-session: git = "https://github.com/Lonami/grammers"
- tera: "1.20"（不得用 2.0-alpha）
- rusqlite: "0.37" features=["bundled"]
- chrono: "0.4" features=["serde"]
- regex: "1"
- serde: "1" features=["derive"]
- serde_json: "1"
- dotenvy: "0.15"
- anyhow: "1"
- tracing: "0.1"
- tracing-subscriber: "0.3" features=["env-filter"]

## 目录结构
hanagram-web/
├── Cargo.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── sessions/
├── templates/
│   └── index.html
└── src/
    ├── main.rs
    ├── state.rs
    └── session_handler.rs

## 核心数据结构（src/state.rs）
严格实现，不得更改字段名：

pub enum SessionStatus { Connecting, Connected, Error(String) }

pub struct OtpMessage {
    pub received_at: DateTime<Utc>,
    pub text: String,
    pub code: Option<String>,  // 正则 r"\b\d{5,6}\b" 提取
}

pub struct SessionInfo {
    pub phone: String,
    pub session_file: PathBuf,
    pub status: SessionStatus,
    pub messages: VecDeque<OtpMessage>,  // 最多 20 条，新消息插队首
}

pub type SharedState = Arc<RwLock<HashMap<String, SessionInfo>>>;

## Telethon Session 转换（session_handler.rs）
1. 用 rusqlite 尝试打开 .session 文件
2. 执行 SQL: SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1
3. 提取 auth_key(BLOB,176字节)、dc_id、server_address、port
4. 构建 grammers_session 兼容的内存 session
5. 若非 SQLite 格式，直接作为 grammers 原生 session 加载
6. 任何错误只记录 tracing::warn! 并跳过，不 panic

## grammers 0.8 事件循环（正确写法）
使用 client.next_update().await，不是旧版 iter_updates()

loop {
    match client.next_update().await {
        Ok(Some(Update::NewMessage(message))) => {
            if let Some(sender) = message.sender() {
                if sender.id() == 777000i64 {
                    let text = message.text().to_string();
                    let code = regex.find(&text).map(|m| m.as_str().to_string());
                    let otp = OtpMessage { received_at: Utc::now(), text, code };
                    // 获取写锁，写入后立即释放，不得在持锁期间 .await
                    let mut state = shared_state.write().await;
                    if let Some(info) = state.get_mut(&key) {
                        info.messages.push_front(otp);
                        info.messages.truncate(20);
                    }
                }
            }
        }
        Ok(None) => break,
        Err(e) => { tracing::error!("Update error: {}", e); break; }
        _ => {}
    }
}

## 多任务架构 & 重连
main.rs 启动：
1. dotenvy::dotenv().ok()
2. 初始化 tracing_subscriber
3. 初始化 SharedState
4. 遍历 SESSIONS_DIR/*.session
5. tokio::spawn(run_session) for each
6. 并行启动 Axum server

重连：指数退避，最多5次，间隔 5/10/20/40/80s
锁规则：持有写锁期间绝对不能 .await

## Web 层（Axum 0.8）
环境变量：AUTH_USER(必须), AUTH_PASS(必须), API_ID(必须), API_HASH(必须), SESSIONS_DIR(默认./sessions), BIND_ADDR(默认0.0.0.0:8080), RUST_LOG(默认info)

路由：
- GET /        → 主页面（Basic Auth 保护）
- GET /health  → {"status":"ok","sessions":N}（无 Auth）

Axum 0.8 路由结构（/health 必须在 auth layer 之外）：
let protected = Router::new().route("/", get(index_handler)).layer(ValidateRequestHeaderLayer::basic(&user, &pass));
let app = Router::new().merge(protected).route("/health", get(health_handler)).with_state(state);

## Tera 模板（templates/index.html）
- 深色主题 TailwindCSS CDN (cdn.tailwindcss.com)
- 顶部：标题 + 账号总数 + 已连接数
- 每账号卡片：手机号、状态指示灯、最新验证码(text-4xl font-mono)、复制按钮(navigator.clipboard)、最近5条消息
- <meta http-equiv="refresh" content="30">
- Tera 变量：sessions: Vec<SessionInfo>, now: String

## Dockerfile（多阶段静态编译）
Stage 1: ghcr.io/rust-cross/rust-musl-cross:x86_64-musl（不得用废弃的 clux/muslrust）
Stage 2: alpine:3.21（含 wget，支持 healthcheck）
HEALTHCHECK: wget -qO- http://localhost:8080/health

## 输出文件（按序完整输出，不得省略）
1. Cargo.toml
2. src/state.rs
3. src/session_handler.rs
4. src/main.rs
5. templates/index.html
6. Dockerfile
7. docker-compose.yml
8. .env.example

## 硬性约束
✗ 禁止 unwrap()，全部用 ? 或 match
✗ 禁止持有 RwLock 写锁时 .await
✗ 禁止 Axum 0.7 的 Extension 写法
✗ 禁止 clux/muslrust Docker 镜像
✗ 禁止 grammers 旧版 iter_updates()
✓ 代码必须能 cargo build --release 通过
✓ 所有文件头部含 AGPLv3 SPDX 声明
✓ session 转换失败只 warn 并跳过
✓ /health 路由在 auth layer 之外
✓ grammers 必须 git 引用