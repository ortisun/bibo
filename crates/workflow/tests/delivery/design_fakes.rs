//! What the design re-check reads before the pull request is opened (DG-8): the issues of the code
//! host, the design rule of the policy, the allowlist, and the place where the comments go. Each is
//! a small stand-in labelled `fake`, with one switch a test turns to break it.
//!
//! The issue source is the testkit's fake behind a wrapper that can be made unreachable, because the
//! fake itself never fails a read.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::ids::TenantId;
use factory_domain::policy::authority::{Allowlist, AllowlistEntry};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::issue_workflow::{DesignGate, ReplyCap};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    ActorLogin, Comment, CommentRef, GitHostError, GitScope, GithubActor, Issue, IssueRef,
    IssueSource, LabelApplication, ProtectionReport,
};
use factory_testkit::githost::FakeIssueSource;
use factory_workflow::stages::intake::{
    AllowlistSource, DesignGatePolicy, RefusalReplies, ReplyError, SeamError,
};

/// The trigger label.
pub const LABEL: &str = "factory";
/// The label of the approved design.
pub const APPROVED: &str = "design: approved";
/// A person who holds the approver designation.
pub const APPROVER_ID: u64 = 2002;
/// A person who holds only the requester designation.
pub const REQUESTER_ID: u64 = 1001;

pub fn person(id: u64, login: &str) -> GithubActor {
    GithubActor {
        id,
        login: ActorLogin::new(login).expect("a login"),
    }
}

/// The issues of the code host: the testkit's fake, which a test can make unreachable.
pub struct Issues {
    inner: FakeIssueSource,
    down: AtomicBool,
    reads: AtomicUsize,
}

impl Issues {
    pub fn new() -> Self {
        Self {
            inner: FakeIssueSource::new(),
            down: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
        }
    }

    pub fn fake(&self) -> &FakeIssueSource {
        &self.inner
    }

    /// Every read fails as if the code host were down.
    pub fn go_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// How many reads were asked for, whatever came of them.
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn read(&self) -> Result<(), GitHostError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            Err(GitHostError::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl IssueSource for Issues {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError> {
        self.read()?;
        self.inner.fetch_issue(scope, issue).await
    }

    async fn fetch_comment(
        &self,
        scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError> {
        self.read()?;
        self.inner.fetch_comment(scope, comment).await
    }

    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<GithubActor>, GitHostError> {
        self.read()?;
        self.inner.label_actor(scope, issue, label).await
    }

    async fn label_application(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<LabelApplication>, GitHostError> {
        self.read()?;
        self.inner.label_application(scope, issue, label).await
    }

    async fn labels_ever_applied(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<Vec<String>, GitHostError> {
        self.read()?;
        self.inner.labels_ever_applied(scope, issue).await
    }

    async fn text_edit(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<factory_ports::githost::TextEdit, GitHostError> {
        self.read()?;
        self.inner.text_edit(scope, issue).await
    }

    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        self.read()?;
        self.inner.repository_protection(scope).await
    }
}

/// The design rule of the policy, which a test can break as a missing file would.
pub struct Rule {
    rule: Mutex<Option<DesignGate>>,
}

impl Rule {
    pub fn new() -> Self {
        Self {
            rule: Mutex::new(Some(factory_testkit::issue_status::design_gate())),
        }
    }

    pub fn break_it(&self) {
        *self.rule.lock().expect("lock") = None;
    }
}

#[async_trait]
impl DesignGatePolicy for Rule {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn current(&self) -> Result<DesignGate, SeamError> {
        self.rule
            .lock()
            .expect("lock")
            .clone()
            .ok_or(SeamError::Unavailable)
    }
}

/// The allowlist: a requester, and an approver who can be taken off the list.
pub struct People {
    approver_listed: AtomicBool,
    unreadable: AtomicBool,
}

impl People {
    pub fn new() -> Self {
        Self {
            approver_listed: AtomicBool::new(true),
            unreadable: AtomicBool::new(false),
        }
    }

    pub fn remove_the_approver(&self) {
        self.approver_listed.store(false, Ordering::SeqCst);
    }

    pub fn break_it(&self) {
        self.unreadable.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl AllowlistSource for People {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn current(&self, tenant: TenantId) -> Result<Allowlist, SeamError> {
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(SeamError::Unavailable);
        }
        let entry = |id: u64, login: &str, designation: Designation| AllowlistEntry {
            tenant,
            github_user_id: GithubUserId::new(id).expect("a numeric id"),
            login: login.to_owned(),
            designations: [designation].into_iter().collect(),
            repositories: None,
            expires_at: None,
        };
        let mut entries = vec![entry(REQUESTER_ID, "requester-one", Designation::Requester)];
        if self.approver_listed.load(Ordering::SeqCst) {
            entries.push(entry(APPROVER_ID, "approver-one", Designation::Approver));
        }
        Allowlist::new("allowlist-v1-test", entries).map_err(|_| SeamError::Unavailable)
    }
}

/// The records the stage writes at once (DR-3), in the order it writes them. The world gives the
/// context this in place of the engine's.
#[derive(Default)]
pub struct Durable {
    records: Mutex<Vec<String>>,
}

impl Durable {
    pub fn records(&self) -> Vec<String> {
        self.records.lock().expect("lock").clone()
    }

    pub fn clear(&self) {
        self.records.lock().expect("lock").clear();
    }
}

#[async_trait]
impl factory_workflow::handlers::DurableRecords for Durable {
    async fn record(
        &self,
        _action: factory_workflow::audit::AuditAction,
        reason: String,
    ) -> Result<(), factory_workflow::handlers::StageError> {
        self.records.lock().expect("lock").push(reason);
        Ok(())
    }
}

/// The comments the stage asked to post, one for each key, as the host keeps them.
pub struct Replies {
    posted: Mutex<Vec<(String, String)>>,
    down: AtomicBool,
    capped: AtomicBool,
    caps: Mutex<Vec<ReplyCap>>,
    /// The records already written at once when each reply was asked for (DR-3).
    durable: Mutex<Option<Arc<Durable>>>,
    durable_at_post: Mutex<Vec<Vec<String>>>,
}

impl Replies {
    pub fn new() -> Self {
        Self {
            posted: Mutex::new(Vec::new()),
            down: AtomicBool::new(false),
            capped: AtomicBool::new(false),
            caps: Mutex::new(Vec::new()),
            durable: Mutex::new(None),
            durable_at_post: Mutex::new(Vec::new()),
        }
    }

    /// From now on, each time a reply is asked for, the records that `durable` already holds are
    /// kept (DR-3).
    pub fn look_at(&self, durable: Arc<Durable>) {
        *self.durable.lock().expect("lock") = Some(durable);
    }

    /// What the durable records held when each reply was asked for, oldest first.
    pub fn durable_at_post(&self) -> Vec<Vec<String>> {
        self.durable_at_post.lock().expect("lock").clone()
    }

    /// The host cannot take a comment now.
    pub fn go_down(&self) {
        self.down.store(true, Ordering::SeqCst);
    }

    /// The issue already holds as many replies as the cap allows (DG-9).
    pub fn reach_the_cap(&self) {
        self.capped.store(true, Ordering::SeqCst);
    }

    /// The cap the stage gave each time it asked, oldest first.
    pub fn caps(&self) -> Vec<ReplyCap> {
        self.caps.lock().expect("lock").clone()
    }

    /// The text of each comment on the issue, oldest first.
    pub fn texts(&self) -> Vec<String> {
        self.posted
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, text)| text.clone())
            .collect()
    }

    pub fn keys(&self) -> Vec<String> {
        self.posted
            .lock()
            .expect("lock")
            .iter()
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[async_trait]
impl RefusalReplies for Replies {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn post(
        &self,
        _tenant: TenantId,
        _issue: &IssueRef,
        key: &str,
        text: &str,
        cap: &ReplyCap,
    ) -> Result<(), ReplyError> {
        self.caps.lock().expect("lock").push(*cap);
        if let Some(durable) = self.durable.lock().expect("lock").clone() {
            self.durable_at_post
                .lock()
                .expect("lock")
                .push(durable.records());
        }
        if self.down.load(Ordering::SeqCst) {
            return Err(ReplyError::Later);
        }
        if self.capped.load(Ordering::SeqCst) {
            return Err(ReplyError::CapReached);
        }
        let mut posted = self.posted.lock().expect("lock");
        if !posted.iter().any(|(held, _)| held == key) {
            posted.push((key.to_owned(), text.to_owned()));
        }
        Ok(())
    }
}

/// The four stand-ins a world is built with, shared with the handler it builds.
pub struct DesignWorld {
    pub issues: Arc<Issues>,
    pub rule: Arc<Rule>,
    pub people: Arc<People>,
    pub replies: Arc<Replies>,
}

impl DesignWorld {
    pub fn new() -> Self {
        Self {
            issues: Arc::new(Issues::new()),
            rule: Arc::new(Rule::new()),
            people: Arc::new(People::new()),
            replies: Arc::new(Replies::new()),
        }
    }
}
