//! The operator command line.
//!
//! ```text
//! factory-cli health   --api URL
//! factory-cli submit   --api URL --token-file FILE --repository ID --text-file FILE [--key K] [--source-ref R]
//! factory-cli status   --api URL --token-file FILE JOB
//! factory-cli timeline --api URL --token-file FILE JOB
//! factory-cli approve  --api URL --token-file FILE [--key K] JOB STAGE_RUN head=H evidence=sha256:D [reason...]
//! factory-cli reject   --api URL --token-file FILE [--key K] JOB STAGE_RUN reason...
//! factory-cli rework   --api URL --token-file FILE [--key K] JOB STAGE_RUN target=STAGE reason...
//! factory-cli pause | resume | cancel  --api URL --token-file FILE [--key K] JOB reason...
//! factory-cli probe    --protected-checkout DIR [--images-catalog FILE] [--profile P]
//! ```
//!
//! The verbs and the words after them are the grammar every channel shares
//! (`factory_composition::commands`), so a decision typed here and in a pull request comment is read
//! by the same function. There is no verb that merges or deploys.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | done |
//! | 1 | the command was not understood, or a local check failed |
//! | 2 | **refused**: the API answered 4xx (not authorized, not allowed, not found, not valid, a conflict) |
//! | 3 | **blocked**: the API is not ready or asked to try later (429, 5xx), or `probe` found something it cannot check (`BLOCKED:` lines) |
//! | 4 | **unreachable**: the API could not be reached or did not answer in time |
//!
//! # Secrets
//!
//! The token is read from a file (a regular file, not a symbolic link, readable by its owner only),
//! never from an argument or an environment variable. It is sent only as `Authorization: Bearer`,
//! over HTTPS or to a loopback address, and is never printed, logged or put in an error message.

pub mod client;
pub mod commands;
pub mod exit;
pub mod probe;
pub mod render;

pub use commands::run;
pub use exit::Exit;
