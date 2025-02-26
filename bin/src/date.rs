// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use chrono::{DateTime, Duration, Timelike, Utc};

/// Parser for datelike command line arguments. Can accept a duration (e.g.
/// "1w") or an ISO8601 timestamp.
pub(crate) fn parse_duration_or_datetime(s: &str) -> Result<DateTime<Utc>> {
    match humantime::parse_duration(s) {
        Ok(duration) => {
            // Remove nanoseconds from the timestamp to keep it less
            // overwhelming. `Timelike::with_nanosecond` returns None only when
            // passed a value over 2 billion
            let now = Utc::now().with_nanosecond(0).unwrap();
            Ok(now + Duration::from_std(duration)?)
        }
        Err(_) => Ok(s.parse()?),
    }
}
