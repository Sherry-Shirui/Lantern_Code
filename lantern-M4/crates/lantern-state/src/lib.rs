#![forbid(unsafe_code)]
#![doc = "Deterministic Lantern application state machine and atomic M2/M3 integration."]

mod authorizer;
mod error;
mod machine;
mod storage;

pub use authorizer::{
    PublicationAuthorizationError, PublicationAuthorizationInput, PublicationAuthorizationV1,
    PublicationAuthorizer,
};
pub use error::{Error, Result};
pub use machine::{PreparedBlock, StateMachine};

#[cfg(test)]
mod tests;
