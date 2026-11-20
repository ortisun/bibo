//! Decorators and scripted transports for the tests that need the network to misbehave.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_github::{Method, Transport, TransportError, WireRequest, WireResponse};
use serde_json::{Value, json};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Forwards every request, and loses the answer of chosen ones: the request reaches the server
/// and has its effect, and the caller sees a dropped connection. This is the failure that makes a
/// retry necessary.
pub struct LosesAnswers {
    inner: Arc<dyn Transport>,
    rules: Mutex<Vec<(Method, String)>>,
}

impl LosesAnswers {
    /// Loses the answer of the next request with this method whose target contains `fragment`.
    pub fn once(inner: Arc<dyn Transport>, method: Method, fragment: &str) -> Arc<Self> {
        Arc::new(Self {
            inner,
            rules: Mutex::new(vec![(method, fragment.to_owned())]),
        })
    }
}

#[async_trait]
impl Transport for LosesAnswers {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        let lose = {
            let mut rules = lock(&self.rules);
            rules
                .iter()
                .position(|(m, f)| *m == request.method && request.target.contains(f.as_str()))
                .map(|p| rules.remove(p))
                .is_some()
        };
        let response = self.inner.execute(request).await;
        if lose {
            Err(TransportError::Connect)
        } else {
            response
        }
    }
}

/// What a server that does not narrow tokens would answer: the mint answer is changed so that it
/// says the token covers more than was asked.
#[derive(Debug, Clone, Copy)]
pub enum Widening {
    /// An extra permission name.
    ExtraPermission,
    /// A higher level on a permission that was asked for.
    HigherLevel,
    /// A second repository.
    SecondRepository,
    /// No `repositories` member at all (an all-repositories token).
    NoRepositoryList,
}

pub struct Widens {
    inner: Arc<dyn Transport>,
    how: Widening,
}

impl Widens {
    pub fn new(inner: Arc<dyn Transport>, how: Widening) -> Arc<Self> {
        Arc::new(Self { inner, how })
    }
}

#[async_trait]
impl Transport for Widens {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        let is_mint = request.method == Method::Post && request.target.ends_with("/access_tokens");
        let mut response = self.inner.execute(request).await?;
        if is_mint && response.status == 201 {
            let mut value: Value = serde_json::from_slice(&response.body).expect("a mint answer");
            match self.how {
                Widening::ExtraPermission => {
                    value["permissions"]["administration"] = json!("write")
                }
                Widening::HigherLevel => value["permissions"]["contents"] = json!("write"),
                Widening::SecondRepository => {
                    let other = json!({"full_name": "example-org/other", "name": "other"});
                    value["repositories"]
                        .as_array_mut()
                        .expect("a list")
                        .push(other);
                }
                Widening::NoRepositoryList => {
                    value
                        .as_object_mut()
                        .expect("an object")
                        .remove("repositories");
                }
            }
            response.body = value.to_string().into_bytes();
        }
        Ok(response)
    }
}

/// Answers from a script and records what it was asked. For rate limits, pagination and links.
pub struct Scripted {
    answers: Mutex<VecDeque<WireResponse>>,
    pub seen: Mutex<Vec<WireRequest>>,
}

impl Scripted {
    pub fn new(answers: Vec<WireResponse>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            seen: Mutex::new(Vec::new()),
        })
    }

    pub fn targets(&self) -> Vec<String> {
        lock(&self.seen).iter().map(|r| r.target.clone()).collect()
    }
}

#[async_trait]
impl Transport for Scripted {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        lock(&self.seen).push(request);
        lock(&self.answers)
            .pop_front()
            .ok_or(TransportError::Connect)
    }
}

/// Forwards every request except the ones a test has scripted an answer for. A scripted answer is
/// used once, for the first request of that method whose target contains the fragment.
pub struct Overrides {
    inner: Arc<dyn Transport>,
    rules: Mutex<Vec<(Method, String, WireResponse)>>,
    seen: Mutex<Vec<(Method, String)>>,
}

impl Overrides {
    pub fn new(inner: Arc<dyn Transport>, rules: Vec<(Method, &str, WireResponse)>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            rules: Mutex::new(
                rules
                    .into_iter()
                    .map(|(m, f, r)| (m, f.to_owned(), r))
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        })
    }

    /// Adds an answer after the ones already scripted.
    pub fn script(&self, method: Method, fragment: &str, response: WireResponse) {
        lock(&self.rules).push((method, fragment.to_owned(), response));
    }

    /// The targets seen so far that contain the fragment.
    pub fn targets_with(&self, fragment: &str) -> Vec<String> {
        lock(&self.seen)
            .iter()
            .filter(|(_, t)| t.contains(fragment))
            .map(|(_, t)| t.clone())
            .collect()
    }
}

#[async_trait]
impl Transport for Overrides {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        lock(&self.seen).push((request.method, request.target.clone()));
        let scripted = {
            let mut rules = lock(&self.rules);
            rules
                .iter()
                .position(|(m, f, _)| *m == request.method && request.target.contains(f.as_str()))
                .map(|p| rules.remove(p).2)
        };
        match scripted {
            Some(response) => Ok(response),
            None => self.inner.execute(request).await,
        }
    }
}

pub fn answer(status: u16, headers: &[(&str, &str)], body: &Value) -> WireResponse {
    WireResponse {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.to_string().into_bytes(),
    }
}
