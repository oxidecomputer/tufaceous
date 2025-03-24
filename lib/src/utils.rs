// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Write;

use anyhow::anyhow;
use indent_write::fmt::IndentWriter;

/// A temporary hack to convert a list of anyhow errors into a single
/// `anyhow::Error`. If no errors are provided, panic (this should be handled
/// at a higher level).
///
/// Eventually we should gain first-class support for representing errors as
/// trees, but this will do for now.
pub(crate) fn merge_anyhow_list<I>(errors: I) -> anyhow::Error
where
    I: IntoIterator<Item = anyhow::Error>,
{
    let mut iter = errors.into_iter().peekable();
    // How many errors are there?
    let Some(first_error) = iter.next() else {
        // No errors: panic.
        panic!("error_list_to_anyhow called with no errors");
    };

    if iter.peek().is_none() {
        // One error.
        return first_error;
    }

    // Multiple errors.
    let mut out = String::new();
    let mut nerrors = 0;
    for error in std::iter::once(first_error).chain(iter) {
        if nerrors > 0 {
            // Separate errors with a newline (we want there to not be a
            // trailing newline to match anyhow generally).
            writeln!(&mut out).unwrap();
        }
        nerrors += 1;
        let mut current: &dyn std::error::Error = error.as_ref();

        let mut writer = IndentWriter::new_skip_initial("  ", &mut out);
        write!(writer, "Error: {current}").unwrap();

        while let Some(cause) = current.source() {
            // This newline is not part of the `IndentWriter`'s output so that
            // it is unaffected by the indent logic.
            writeln!(&mut out).unwrap();

            // The spaces align the causes with the "Error: " above.
            let mut writer =
                IndentWriter::new_skip_initial("       ", &mut out);
            write!(writer, "     - {cause}").unwrap();
            current = cause;
        }
    }
    anyhow!(out).context(format!("{nerrors} errors encountered"))
}
