/*
 * SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
 * SPDX-FileCopyrightText: 2025 NightProg <tonio.barbier@gmail.com>
 * SPDX-License-Identifier: MPL-2.0
 */

#[derive(Debug, Clone)]
pub struct Url {
    ip: String,
    port: u16,
}

impl Url {
    pub fn new(ip: String, port: u16) -> Self {
        Self { ip, port }
    }
}

impl TryFrom<&str> for Url {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();

        if parts.len() != 2 {
            Err("Invalid URL format".to_string())
        } else {
            let ip = parts[0].to_string();
            let port = parts[1]
                .parse()
                .map_err(|_| "Invalid port number".to_string())?;

            Ok(Self { ip, port })
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    url: Url,
    user: String,
}

impl Target {
    pub fn new(url: Url, user: String) -> Self {
        Self { url, user }
    }
}

impl TryFrom<String> for Target {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('@').collect();

        if parts.len() != 2 {
            Err("Invalid target format".to_string())
        } else {
            Ok(Self {
                url: Url::try_from(parts[0])?,
                user: parts[1].to_string(),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionLoginInfo {
    pub target: Target,
    pub password: String,
}
