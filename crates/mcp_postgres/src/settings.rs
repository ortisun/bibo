//! Where the database is and who the server logs in as.

use std::fmt;

/// A password read from a file at start. Never printed: `Debug` shows a placeholder.
#[derive(Clone)]
pub struct Password(String);

impl Password {
    /// Wraps a password. The caller reads it from a file, never from an argument or the
    /// environment, and registers it with the redactor.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value, for the connection and for registering it with the redactor.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([hidden])")
    }
}

/// The connection settings. `host` is a name, an address, or the directory of a Unix socket
/// (an absolute path). No TLS: as in the storage crate, the connection is made without it and a
/// TLS setup is a deployment item.
#[derive(Debug, Clone)]
pub struct ConnectSettings {
    /// Host name, address or socket directory.
    pub host: String,
    /// Port.
    pub port: u16,
    /// The login, a member of `factory_observer` (normally `factory_troubleshooter`).
    pub user: String,
    /// The database name.
    pub database: String,
    password: Option<Password>,
}

impl ConnectSettings {
    /// Settings without a password (trust or peer authentication).
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        database: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            database: database.into(),
            password: None,
        }
    }

    /// The same settings with a password.
    #[must_use]
    pub fn with_password(mut self, password: Password) -> Self {
        self.password = Some(password);
        self
    }

    /// The password, if any.
    pub fn password(&self) -> Option<&Password> {
        self.password.as_ref()
    }

    pub(crate) fn driver_config(&self, limits: &crate::Limits) -> tokio_postgres::Config {
        let mut config = tokio_postgres::Config::new();
        config
            .host(&self.host)
            .port(self.port)
            .user(&self.user)
            .dbname(&self.database)
            .application_name("factory-mcp-postgres")
            .connect_timeout(limits.connect_timeout);
        if let Some(password) = &self.password {
            config.password(password.expose());
        }
        config
    }
}
