// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use tough::async_trait;
use tough::key_source::KeySource;
use tough::schema::key::Key;
use tough::sign::Sign;

use crate::error::Error;
use crate::error::ErrorKind;

#[derive(Debug, Clone)]
pub struct Ed25519Key(Arc<Ed25519KeyPair>);

impl Ed25519Key {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(Arc::new(
            Ed25519KeyPair::generate()
                .map_err(|Unspecified| ErrorKind::Ed25519Generate)?,
        )))
    }
}

#[async_trait]
impl Sign for Ed25519Key {
    fn tuf_key(&self) -> Key {
        self.0.tuf_key()
    }

    async fn sign(
        &self,
        msg: &[u8],
        rng: &(dyn SecureRandom + Sync),
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        Sign::sign(self.0.as_ref(), msg, rng).await
    }
}

#[async_trait]
impl KeySource for Ed25519Key {
    async fn as_sign(
        &self,
    ) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        Ok(Box::new(self.clone()))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }
}
