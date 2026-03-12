// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub enum SessionStatus {
    Connecting,
    Connected,
    Error(String),
}

impl SessionStatus {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Error(_) => "error",
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            Self::Error(message) => Some(message.as_str()),
            Self::Connecting | Self::Connected => None,
        }
    }
}

impl Serialize for SessionStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut status = serializer.serialize_struct("SessionStatus", 3)?;
        status.serialize_field("kind", self.kind())?;
        status.serialize_field("connected", &self.is_connected())?;
        status.serialize_field("error", &self.error_message())?;
        status.end()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OtpMessage {
    pub received_at: DateTime<Utc>,
    pub text: String,
    pub code: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub phone: String,
    pub session_file: PathBuf,
    pub status: SessionStatus,
    pub messages: VecDeque<OtpMessage>,
}

impl SessionInfo {
    pub fn latest_code(&self) -> Option<&str> {
        self.messages
            .front()
            .and_then(|message| message.code.as_deref())
    }

    pub fn recent_messages(&self) -> Vec<OtpMessage> {
        self.messages.iter().take(5).cloned().collect()
    }
}

impl Serialize for SessionInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let session_file = self.session_file.display().to_string();
        let latest_code = self.latest_code();
        let recent_messages = self.recent_messages();

        let mut info = serializer.serialize_struct("SessionInfo", 6)?;
        info.serialize_field("phone", &self.phone)?;
        info.serialize_field("session_file", &session_file)?;
        info.serialize_field("status", &self.status)?;
        info.serialize_field("messages", &self.messages)?;
        info.serialize_field("latest_code", &latest_code)?;
        info.serialize_field("recent_messages", &recent_messages)?;
        info.end()
    }
}

pub type SharedState = Arc<RwLock<HashMap<String, SessionInfo>>>;
