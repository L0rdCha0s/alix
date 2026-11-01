//! Native byte-preserving extensions for Alix paths and OS strings.
#![stable(feature = "alix_os", since = "1.97.1")]

// Alix selects std's byte OsString backend. Reuse the upstream extensions
// without publishing a Unix module or changing the target family.
#[path = "../unix/ffi/os_str.rs"]
mod os_str;

#[stable(feature = "alix_os", since = "1.97.1")]
pub use self::os_str::{OsStrExt, OsStringExt};
