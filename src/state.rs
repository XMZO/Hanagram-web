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

#[derive(Clone, Debug)]
pub struct OtpMessage {
    pub received_at: DateTime<Utc>,
    pub text: String,
    pub code: Option<String>,
}

impl Serialize for OtpMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let received_at = self.received_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let mut message = serializer.serialize_struct("OtpMessage", 3)?;
        message.serialize_field("received_at", &received_at)?;
        message.serialize_field("text", &self.text)?;
        message.serialize_field("code", &self.code)?;
        message.end()
    }
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub key: String,
    pub note: String,
    pub phone: String,
    pub session_file: PathBuf,
    pub status: SessionStatus,
    pub messages: VecDeque<OtpMessage>,
}

impl SessionInfo {
    pub fn latest_message(&self) -> Option<&OtpMessage> {
        self.messages.front()
    }

    pub fn latest_code(&self) -> Option<&str> {
        self.latest_message()
            .and_then(|message| message.code.as_deref())
    }

    pub fn latest_code_message(&self) -> Option<&OtpMessage> {
        self.messages.iter().find(|message| message.code.is_some())
    }

    pub fn recent_messages(&self) -> Vec<OtpMessage> {
        self.messages.iter().take(5).cloned().collect()
    }

    pub fn notification_context(&self) -> SessionNotificationContext {
        SessionNotificationContext {
            user_id: self.user_id.clone(),
            key: self.key.clone(),
            phone: self.phone.clone(),
            session_file: self.session_file.clone(),
            status: self.status.clone(),
        }
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
        let latest_message_at = self.latest_message().map(|message| {
            message
                .received_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
        });
        let latest_code_at_unix = self
            .latest_code_message()
            .map(|message| message.received_at.timestamp());

        let mut info = serializer.serialize_struct("SessionInfo", 11)?;
        info.serialize_field("id", &self.id)?;
        info.serialize_field("user_id", &self.user_id)?;
        info.serialize_field("key", &self.key)?;
        info.serialize_field("note", &self.note)?;
        info.serialize_field("phone", &self.phone)?;
        info.serialize_field("session_file", &session_file)?;
        info.serialize_field("status", &self.status)?;
        info.serialize_field("latest_code", &latest_code)?;
        info.serialize_field("latest_message_at", &latest_message_at)?;
        info.serialize_field("latest_code_at_unix", &latest_code_at_unix)?;
        info.serialize_field("recent_messages", &recent_messages)?;
        info.end()
    }
}

#[derive(Clone, Debug)]
pub struct SessionNotificationContext {
    pub user_id: String,
    pub key: String,
    pub phone: String,
    pub session_file: PathBuf,
    pub status: SessionStatus,
}

pub type SharedState = Arc<RwLock<HashMap<String, SessionInfo>>>;
