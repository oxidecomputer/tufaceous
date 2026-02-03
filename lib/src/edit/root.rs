// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::num::NonZero;

use aws_lc_rs::rand::SystemRandom;
use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use tough::editor::signed::SignedRole;
use tough::key_source::KeySource;
use tough::schema;
use tough::schema::KeyHolder;
use tough::schema::RoleKeys;
use tough::schema::RoleType;
use tough::schema::Signed;

use crate::error::Error;
use crate::error::ErrorKind;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Root(Signed<schema::Root>);

impl Root {
    pub async fn generate(
        keys: &[Box<dyn KeySource>],
        expires: DateTime<Utc>,
    ) -> Result<Self, Error> {
        Ok(Self(generate_root(keys, expires).await?.signed().clone()))
    }

    pub fn verify_self_signed(&self) -> Result<(), Error> {
        self.0.signed.verify_role(&self.0).map_err(ErrorKind::RoleVerify)?;
        Ok(())
    }
}

pub(crate) async fn generate_root(
    keys: &[Box<dyn KeySource>],
    expires: DateTime<Utc>,
) -> Result<SignedRole<schema::Root>, Error> {
    let mut root = schema::Root {
        spec_version: "1.0.0".into(),
        consistent_snapshot: false,
        version: NonZero::<u64>::MIN,
        expires,
        keys: HashMap::new(),
        roles: HashMap::new(),
        _extra: HashMap::new(),
    };

    for key in keys {
        let key = key.as_sign().await.map_err(ErrorKind::ToughKey)?.tuf_key();
        root.keys.insert(key.key_id().map_err(ErrorKind::KeyId)?, key);
    }
    for role_type in [
        RoleType::Root,
        RoleType::Snapshot,
        RoleType::Targets,
        RoleType::Timestamp,
    ] {
        root.roles.insert(
            role_type,
            RoleKeys {
                keyids: root.keys.keys().cloned().collect(),
                threshold: NonZero::<u64>::MIN,
                _extra: HashMap::new(),
            },
        );
    }

    Ok(SignedRole::new(
        root.clone(),
        &KeyHolder::Root(root),
        keys,
        &SystemRandom::new(),
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::edit::Ed25519Key;
    use crate::edit::Root;

    #[tokio::test]
    async fn generate_verify() {
        let key = Ed25519Key::generate().unwrap();
        let root = Root::generate(&[Box::new(key)], Utc::now()).await.unwrap();
        root.verify_self_signed().unwrap();
    }
}
