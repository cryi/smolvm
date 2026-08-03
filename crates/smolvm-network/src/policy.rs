//! Pluggable egress policy for the virtio-net backend.
//!
//! Context
//! =======
//!
//! The gateway terminates every guest flow itself, so it is the one place that
//! decides what a guest may reach — and that decision belongs to whoever embeds
//! the gateway, not this crate. It used to be fixed: the `allowed_cidrs` +
//! `--allow-host` allow-list in [`crate::egress`], compiled in. An embedder
//! wanting other grants — a port on a rule, a name the gateway answers itself,
//! a stand-in address for a host-local service — had nowhere to put them but
//! that file.
//!
//! So the decision is a trait. The gateway keeps the mechanism (terminating
//! flows, intercepting DNS, relaying) and asks a [`Policy`] as it goes:
//!
//! ```text
//! guest TCP SYN / UDP datagram
//!   -> allows(ip, port)?
//!        no  -> dropped before any host socket exists
//!        yes -> rewrite(ip)? -> dial that instead, else dial ip as-is
//!
//! guest :53 query  (UDP always; TCP too when intercepts_dns())
//!   -> dns(query)
//!        Immediate(bytes)  -> answered here, nothing leaves the host
//!        Forward { learn } -> forwarded upstream, and if learn the answer
//!                             comes back through learn(answer)
//! ```
//!
//! [`crate::egress::EgressPolicy`] implements the trait with the
//! `allowed_cidrs` + `--allow-host` semantics libkrun's TSI path uses, and is
//! what the launchers build — the default, not the only shape. A policy reaches
//! the relay threads as [`Egress`], which is cloned into each of them.

use std::net::IpAddr;
use std::sync::Arc;

/// What the gateway should do with one guest DNS query.
pub enum DnsVerdict {
    /// Answer the guest with these raw DNS bytes, no upstream query — a
    /// refusal is an answer too (NXDOMAIN, SERVFAIL).
    Immediate(Vec<u8>),
    /// Forward the query upstream; `learn` true echoes the answer back through
    /// [`Policy::learn`] when it arrives.
    Forward { learn: bool },
}

/// The egress policy the gateway enforces. Every method runs on the gateway's
/// poll thread: keep them cheap and non-blocking, no host I/O.
pub trait Policy: Send + Sync {
    /// Whether an outbound flow to `ip` may be opened. `port` is `None` for a
    /// portless flow (an ICMP echo), which only an any-port rule covers.
    /// Called before any host socket exists, so a denial just fails the
    /// connection.
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool;

    /// The address to dial in place of `ip` — the real destination behind a
    /// stand-in this policy published. The guest-facing socket keeps `ip`, so
    /// replies still come addressed as the guest dialed. `None` (the default)
    /// dials `ip` unchanged.
    ///
    /// [`Self::allows`] judges the guest's address, never the rewrite:
    /// publishing the stand-in is what authorizes the target, so an
    /// unpublished stand-in is denied there, not translated here.
    fn rewrite(&self, _ip: IpAddr) -> Option<IpAddr> {
        None
    }

    /// What to do with a guest DNS query; the default forwards it.
    fn dns(&self, _query: &[u8]) -> DnsVerdict {
        DnsVerdict::Forward { learn: false }
    }

    /// An upstream answer to a query [`Self::dns`] asked to learn from; the
    /// answer echoes its question, so the name is recoverable.
    fn learn(&self, _answer: &[u8]) {}

    /// Whether every DNS query must reach [`Self::dns`], even TCP/53 to a
    /// resolver the guest picked. A name-*filtering* policy can leave this
    /// false (an unlisted resolver is already blocked by [`Self::allows`]); a
    /// name-*answering* one must set it, or the guest's own resolver quietly
    /// wins.
    fn intercepts_dns(&self) -> bool {
        false
    }
}

/// A shared handle to the policy in force, cheap to clone into the gateway's
/// relay threads.
pub type Egress = Arc<dyn Policy>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The least a policy can implement.
    struct AllowAll;

    impl Policy for AllowAll {
        fn allows(&self, _ip: IpAddr, _port: Option<u16>) -> bool {
            true
        }
    }

    /// The defaults are what a policy inherits by saying nothing, so they are
    /// part of the contract: saying nothing must not opt a policy into
    /// rewriting destinations, answering DNS, or swallowing the guest's own
    /// resolver.
    #[test]
    fn the_defaults_add_nothing_a_policy_did_not_ask_for() {
        let p: &dyn Policy = &AllowAll;
        assert_eq!(p.rewrite("1.1.1.1".parse().unwrap()), None);
        assert!(matches!(p.dns(&[]), DnsVerdict::Forward { learn: false }));
        assert!(!p.intercepts_dns());
        p.learn(&[]); // must not panic on an answer it never asked for
    }

    /// Everything an embedder can plug in, reached through the handle the
    /// gateway actually holds — so this covers the dynamic dispatch too, not
    /// just the trait in the abstract.
    #[test]
    fn a_custom_policy_answers_every_hook_through_the_handle() {
        struct Custom;

        const STANDIN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        const REAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

        impl Policy for Custom {
            fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
                ip == STANDIN && port == Some(5432)
            }

            fn rewrite(&self, ip: IpAddr) -> Option<IpAddr> {
                (ip == STANDIN).then_some(REAL)
            }

            fn dns(&self, _query: &[u8]) -> DnsVerdict {
                DnsVerdict::Immediate(vec![0xde, 0xad])
            }

            fn intercepts_dns(&self) -> bool {
                true
            }
        }

        let egress: Egress = Arc::new(Custom);
        let other: IpAddr = "1.1.1.1".parse().unwrap();

        // Per-port grants — what the built-in allow-list has no way to say.
        assert!(egress.allows(STANDIN, Some(5432)));
        assert!(!egress.allows(STANDIN, Some(22)));
        assert!(!egress.allows(STANDIN, None));
        assert!(!egress.allows(other, Some(5432)));

        // A stand-in the policy published is dialed as what it stands for;
        // anything else is dialed as itself.
        assert_eq!(egress.rewrite(STANDIN), Some(REAL));
        assert_eq!(egress.rewrite(other), None);

        // The policy answers DNS itself, so the gateway must stop the guest's
        // own resolver from going around it.
        assert!(matches!(egress.dns(&[]), DnsVerdict::Immediate(b) if b == [0xde, 0xad]));
        assert!(egress.intercepts_dns());

        // Cloning the handle shares the policy rather than copying it.
        let cloned = egress.clone();
        assert!(cloned.allows(STANDIN, Some(5432)));
        assert_eq!(Arc::strong_count(&egress), 2);
    }
}
