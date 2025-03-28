// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use tufaceous_lib::Key;

fn print_hint(hint: &str) {
    for line in hint.trim().lines() {
        eprintln!("{}", console::style(format!("hint: {}", line)).yellow());
    }
}

pub(crate) fn generated_key(key: &Key) {
    print_hint(&format!(
        r#"
Generated a random key:

  {key}

To modify this repository, you will need this key. Use the -k/--key
command line flag or the TUFACEOUS_KEY environment variable:

  export TUFACEOUS_KEY={key}

To prevent this default behavior, use --no-generate-key.
        "#,
        key = console::style(key).italic()
    ))
}
