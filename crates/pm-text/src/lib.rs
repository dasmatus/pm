//! Small text-formatting helpers shared by pm's crates and binaries.

use std::{
    fmt::{Display, Write as _},
    iter::IntoIterator,
};

/// Join `items` with `", "` without collecting them into an intermediate `Vec`.
pub fn comma_join<I>(items: I) -> String
where
    I: IntoIterator,
    I::Item: Display,
{
    let mut out = String::new();
    for (position, item) in items.into_iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{item}");
    }
    out
}

/// Flatten anything that would move the cursor out of the line it is on.
///
/// A message is usually a line of a build's own output, which is free to carry
/// carriage returns, tabs and escape sequences. Any of those inside the region
/// desynchronises the redraw from what is on screen.
pub fn collapse_control(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' {
                ' '
            } else if c.is_control() {
                '\u{fffd}'
            } else {
                c
            }
        })
        .filter(|c| *c != '\u{fffd}')
        .collect()
}

/// The single choke point untrusted text passes through before it can reach
/// a wire type.
///
/// A build file is untrusted input, and its commands' stdout reaches these
/// strings verbatim - a package's own `make` output becomes a progress
/// message, and a failed step's captured stdout AND stderr become a
/// `pm_wire::types::Diagnostic`. Every wire constructor that carries
/// build-controlled text MUST pass it through here first: pm-progress's
/// `Task::set_message` does, and so does `From<&miette::Report> for
/// Diagnostic` in `pm_wire::error`.
///
/// Two things happen, in order: control characters are collapsed by reusing
/// [`collapse_control`] - the same logic that already protects the terminal
/// render from a carriage return or an escape sequence - and the result is
/// truncated to `cap` characters. A truncated result always ends in a
/// visible `…` so a capped message is never mistaken for one that simply
/// ended there.
#[must_use]
pub fn sanitise(text: &str, cap: usize) -> String {
    let collapsed = collapse_control(text);
    if collapsed.chars().count() <= cap {
        return collapsed;
    }
    if cap == 0 {
        return String::new();
    }

    let mut truncated: String = collapsed.chars().take(cap - 1).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::comma_join;

    #[test]
    fn joins_with_commas() {
        assert_eq!(comma_join(["a", "b", "c"]), "a, b, c");
        assert_eq!(comma_join([1, 2]), "1, 2");
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(comma_join(Vec::<String>::new()), "");
        assert_eq!(comma_join(["only"]), "only");
    }
}
