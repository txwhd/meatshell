use super::ConfigStore;
use crate::totp::MfaProfile;
use anyhow::{bail, Result};

impl ConfigStore {
    pub fn mfa_profiles(&self) -> &[MfaProfile] {
        &self.cache.mfa_profiles
    }
    pub fn mfa_profile(&self, id: &str) -> Option<&MfaProfile> {
        self.cache
            .mfa_profiles
            .iter()
            .find(|profile| profile.id == id)
    }
    pub fn put_mfa_profile(&mut self, profile: MfaProfile) -> Result<()> {
        profile.validate()?;
        let previous = self.cache.mfa_profiles.clone();
        if let Some(existing) = self
            .cache
            .mfa_profiles
            .iter_mut()
            .find(|p| p.id == profile.id)
        {
            *existing = profile;
        } else {
            if profile.id.is_empty() {
                bail!("MFA entry ID is empty");
            }
            self.cache.mfa_profiles.push(profile);
        }
        if let Err(error) = self.save() {
            self.cache.mfa_profiles = previous;
            return Err(error);
        }
        Ok(())
    }
    pub fn delete_mfa_profile(&mut self, id: &str) -> Result<()> {
        let profiles = self.cache.mfa_profiles.clone();
        let sessions = self.cache.sessions.clone();
        self.cache.mfa_profiles.retain(|profile| profile.id != id);
        for session in &mut self.cache.sessions {
            if session.mfa_profile_id == id {
                session.mfa_profile_id.clear();
            }
        }
        if let Err(error) = self.save() {
            self.cache.mfa_profiles = profiles;
            self.cache.sessions = sessions;
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{fixture_store, Secret, Session};
    fn profile() -> MfaProfile {
        MfaProfile::from_input(
            "mfa-test".into(),
            "Fixture",
            "JBSWY3DPEHPK3PXP",
            "SHA1",
            6,
            30,
        )
        .unwrap()
    }
    #[test]
    fn secrets_are_encrypted_deleted_refs_cannot_return_and_exports_are_unbound() {
        let path = std::env::temp_dir().join(format!("ms-mfa-{}.json", uuid::Uuid::new_v4()));
        let mut store = fixture_store(path.clone(), Vec::new());
        store.put_mfa_profile(profile()).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("JBSWY3DPEHPK3PXP"));
        assert!(raw.contains("enc:v1:"));
        let mut session = Session::new_empty();
        session.name = "fixture".into();
        session.host = "fixture.invalid".into();
        session.mfa_profile_id = "mfa-test".into();
        store.upsert(session.clone());
        store.save().unwrap();
        let (export, _) = store.export_json().unwrap();
        assert!(!export.contains("JBSWY"));
        assert!(!export.contains("mfa-test"));
        store.delete_mfa_profile("mfa-test").unwrap();
        assert!(store.sessions()[0].mfa_profile_id.is_empty());
        store.upsert(session); // Old editor draft must not revive a deleted binding.
        assert!(store.sessions()[0].mfa_profile_id.is_empty());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn mfa_imports_cannot_bind_to_local_profiles_or_replace_their_secrets() {
        let path = std::env::temp_dir().join(format!("ms-mfa-{}.json", uuid::Uuid::new_v4()));
        let mut store = fixture_store(path.clone(), Vec::new());
        store.put_mfa_profile(profile()).unwrap();
        let mut session = Session::new_empty();
        session.name = "Imported fixture".into();
        session.host = "fixture.invalid".into();
        session.mfa_profile_id = "mfa-test".into();
        let mut incoming = profile();
        incoming.secret = Secret::new("GEZDGNBVGY3TQOJQ");
        let raw = serde_json::json!({"sessions": [session], "mfa_profiles": [incoming]}).to_string();
        assert_eq!(store.import_json(&raw).unwrap(), (1, 0));
        assert!(store.sessions()[0].mfa_profile_id.is_empty());
        assert_eq!(store.mfa_profiles().len(), 1);
        assert_eq!(store.mfa_profile("mfa-test").unwrap().secret.as_str(), "JBSWY3DPEHPK3PXP");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_save_rolls_back_profile_and_reference_changes() {
        let path = std::env::temp_dir().join(format!("ms-mfa-{}.json", uuid::Uuid::new_v4()));
        let mut store = fixture_store(path.clone(), Vec::new());
        store.put_mfa_profile(profile()).unwrap();
        std::fs::write(&path, "another writer").unwrap();
        assert!(store.delete_mfa_profile("mfa-test").is_err());
        assert!(store.mfa_profile("mfa-test").is_some());
        let mut changed = profile();
        changed.secret = Secret::new("GEZDGNBVGY3TQOJQ");
        assert!(store.put_mfa_profile(changed).is_err());
        assert_eq!(
            store.mfa_profile("mfa-test").unwrap().secret.as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        let _ = std::fs::remove_file(path);
    }
}
