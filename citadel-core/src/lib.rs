//! Citadel Core - Runtime enforcement and security-critical state management
//!
//! This crate provides the StateEnforcer - layer 1 of the two-layer enforcement boundary. StateEnforcer handles
//! identity, lifecycle, domain, and operation-type. Keystore handles
//! cryptographic role, key state, replay, and execution.
//! all security-critical operations in Citadel.

pub mod state_enforcer;

pub use state_enforcer::{
    AuthorizedContext, DenialReason, LifecycleState, OperationType, StateEnforcer,
};
