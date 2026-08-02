//! The gateway's egress decision points, as a trait the consumer can implement.
//!
//! The gateway terminates every guest flow itself, so it is the one place that
//! decides what a guest may reach. That decision is *policy*, and policy belongs
//! to whoever embeds the gateway — this crate supplies the mechanism and asks
//! four questions:
//!
//! - [`Policy::allows`] — may this flow be opened? (the only mandatory one)
//! - [`Policy::rewrite`] — dial something other than the address the guest used
//! - [`Policy::dns`] — forward, answer, or refuse a guest DNS query
//! - [`Policy::learn`] — here is an answer you asked to see
//!
//! [`AllowListPolicy`](crate::egress::AllowListPolicy) implements it with the
//! `allowed_cidrs` + `--allow-host` semantics libkrun's TSI path uses, and is
//! what every [`EgressPolicy`] constructor here builds. An embedder wanting
//! per-port grants, names the gateway answers itself, or a stand-in address for
//! a host-local service writes its own implementation and passes it to
//! [`EgressPolicy::custom`] rather than growing this crate.

use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

use crate::egress::AllowListPolicy;

/// What the gateway should do with one guest DNS query.
pub enum DnsVerdict {
    /// Answer the guest immediately with these raw DNS message bytes (a refusal
    /// is an answer: NXDOMAIN for a blocked name, SERVFAIL for an unparseable
    /// one). No upstream query is made.
    Immediate(Vec<u8>),
    /// Forward the query upstream; `learn` asks for the answer to come back
    /// through [`Policy::learn`] when it arrives.
    Forward { learn: bool },
}

/// The egress policy the gateway enforces. See the module docs.
///
/// Every method is called on the gateway's poll thread, so keep them cheap and
/// non-blocking — no host I/O.
pub trait Policy: Send + Sync {
    /// Whether an outbound flow to `ip` may be opened. `port` is `None` for a
    /// portless flow (an ICMP echo), which only an any-port rule covers.
    ///
    /// Called before any host socket exists, so a denial is invisible to the
    /// guest beyond the connection simply failing.
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool;

    /// The address to dial in place of `ip`, for a policy that published a
    /// stand-in address to the guest and kept the real destination to itself.
    /// The guest-facing socket keeps `ip` either way, so replies still come back
    /// addressed from the address the guest used. `None` (the default) dials
    /// `ip` unchanged.
    ///
    /// [`Self::allows`] judges the address the *guest* used, never the rewrite —
    /// publishing a stand-in is the policy authorizing that target, so a stand-in
    /// nobody published must be denied there rather than translated here.
    fn rewrite(&self, _ip: IpAddr) -> Option<IpAddr> {
        None
    }

    /// What to do with a guest DNS query. The default forwards everything and
    /// learns nothing.
    fn dns(&self, _query: &[u8]) -> DnsVerdict {
        DnsVerdict::Forward { learn: false }
    }

    /// An upstream answer to a query [`Self::dns`] asked to learn from. The
    /// answer echoes its own question, so the name is recoverable from it.
    fn learn(&self, _answer: &[u8]) {}

    /// Whether every DNS query must reach [`Self::dns`], including TCP/53 to a
    /// resolver the guest picked itself. A policy that only *filters* names can
    /// leave this false (a guest reaching an unlisted resolver is already
    /// blocked by [`Self::allows`]); a policy that *answers* names must set it,
    /// or the guest's own resolver quietly wins over the answer.
    fn intercepts_dns(&self) -> bool {
        false
    }
}

/// A shared handle to the policy in force, cheap to clone into the gateway's
/// relay threads.
#[derive(Clone)]
pub struct EgressPolicy(Arc<dyn Policy>);

impl EgressPolicy {
    /// Plug in any policy.
    pub fn custom(policy: Arc<dyn Policy>) -> Self {
        Self(policy)
    }

    /// The built-in allow-list: no lists at all, i.e. allow everything except
    /// the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self::new(None, None)
    }

    /// The built-in allow-list over `allowed_cidrs` + `--allow-host` names.
    /// Both `None` is [`Self::unrestricted`]; either one `Some` puts the list in
    /// force.
    pub fn new(allowed_cidrs: Option<&[String]>, allowed_hosts: Option<&[String]>) -> Self {
        Self(Arc::new(AllowListPolicy::new(allowed_cidrs, allowed_hosts)))
    }

    /// The built-in allow-list with addresses only and no name filtering.
    pub fn from_allowed_cidrs(allowed_cidrs: Option<&[String]>) -> Self {
        Self::new(allowed_cidrs, None)
    }
}

impl Deref for EgressPolicy {
    type Target = dyn Policy;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
