//! Remember passwords in the OS credential store (Windows Credential Manager,
//! DPAPI-encrypted per user) instead of in sessions.json, which is plaintext.
//!
//! Mirrors PuTTY's design trade-off: PuTTY itself refuses to store passwords,
//! but for a personal tool the convenience of "click ▶ and you are in" wins —
//! as long as the secret never touches the config file. Each session is keyed
//! by its target string (`user@host[:port]`), so renaming a session keeps its
//! credential.

use keyring::Entry;

const SERVICE: &str = "pt-rs";

fn entry(target: &str) -> Option<Entry> {
    Entry::new(SERVICE, target).ok()
}

/// Fetch the stored password for a session target, if any.
pub fn get(target: &str) -> Option<String> {
    let e = entry(target)?;
    match e.get_password() {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    }
}

/// Store (or overwrite) the password for a session target.
pub fn set(target: &str, password: &str) -> Result<(), String> {
    let e = entry(target).ok_or("cannot open the credential store")?;
    e.set_password(password).map_err(|e| e.to_string())
}

/// Remove the stored password (used when the server rejects it, so a stale
/// secret cannot lock the user out, and when a session is deleted).
pub fn delete(target: &str) {
    if let Some(e) = entry(target) {
        let _ = e.delete_credential();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roundtrip against the real (Windows) credential store, under a name
    /// reserved for tests, cleaning up afterwards.
    #[test]
    fn set_get_delete_roundtrip() {
        let target = "pt-rs-selftest";
        delete(target);
        assert_eq!(get(target), None);
        set(target, "s3cret").expect("set_password");
        assert_eq!(get(target).as_deref(), Some("s3cret"));
        set(target, "rotated").expect("overwrite");
        assert_eq!(get(target).as_deref(), Some("rotated"));
        delete(target);
        assert_eq!(get(target), None);
    }
}
