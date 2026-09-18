//! The systemd unit-file format, parsed once for the three plugins that read it.
//!
//! systemd uses one syntax for a great many things. A `.service` unit, a
//! `systemd-sysupdate` transfer definition and a `systemd-repart` partition definition
//! are all the same file format - sections in brackets, `Key=Value` lines, `#` and `;`
//! comments, values continued across lines with a trailing `\` - so the three plugins in
//! this workspace share one reader rather than each growing their own.
//!
//! It is an ordinary Rust library. Nothing about a plugin stops you depending on one:
//! a component is compiled from a normal crate graph, and only the outermost crate has
//! to be a `cdylib` exporting the world.
//!
//! # What this is not
//!
//! Not a validator. It reports what a file *says*, including things systemd would
//! reject, because a plugin's job is to read a file that is already on disk rather than
//! to judge it. Directives it cannot make sense of come back as they were written and
//! the caller decides.

#![forbid(unsafe_code)]

/// One `Key=Value` line, and where it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// The `[Section]` it appeared under, without the brackets. Empty before the first
    /// section header - which systemd rejects, but which is not this module's business.
    pub section: String,
    /// The part before the first `=`, trimmed.
    pub key: String,
    /// The part after the first `=`, trimmed, with any line continuations folded in.
    pub value: String,
    /// 1-based line the directive started on, for evidence lines.
    pub line: usize,
}

impl Directive {
    /// Whether this directive is `key` in `section`, ignoring case in both.
    ///
    /// systemd matches section and directive names case-sensitively in practice, but
    /// hand-written units are full of `ExecStart` spelled six ways and a plugin that
    /// misses one silently narrows a profile. Case-insensitive is the forgiving
    /// direction, and the cost of being wrong is a grant that a human then reads.
    #[must_use]
    pub fn is(&self, section: &str, key: &str) -> bool {
        self.section.eq_ignore_ascii_case(section) && self.key.eq_ignore_ascii_case(key)
    }

    /// Whether this directive is `key` in any of `sections`.
    #[must_use]
    pub fn is_any(&self, sections: &[&str], key: &str) -> bool {
        sections.iter().any(|section| self.is(section, key))
    }
}

/// Read a unit file into its directives, in the order they appear.
///
/// Handles what the format actually contains:
///
/// * `#` and `;` comment lines, and blank lines;
/// * `[Section]` headers;
/// * a trailing `\` continuing a value onto the next line, which systemd folds into a
///   single space;
/// * leading and trailing whitespace around both halves of a `Key=Value`.
///
/// A line that is neither a comment, a section header nor a `Key=Value` is skipped.
#[must_use]
pub fn parse(text: &str) -> Vec<Directive> {
    let mut directives = Vec::new();
    let mut section = String::new();
    // The continuation being folded, and the line it started on.
    let mut pending: Option<(String, usize)> = None;

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();

        if let Some((mut carried, started)) = pending.take() {
            match line.strip_suffix('\\') {
                Some(more) => {
                    carried.push(' ');
                    carried.push_str(more.trim_end());
                    pending = Some((carried, started));
                }
                None => {
                    carried.push(' ');
                    carried.push_str(line);
                    push(&mut directives, &section, &carried, started);
                }
            }
            continue;
        }

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_owned();
            continue;
        }
        match line.strip_suffix('\\') {
            Some(start) => pending = Some((start.trim_end().to_owned(), number)),
            None => push(&mut directives, &section, line, number),
        }
    }

    // A file ending mid-continuation still said something; keep it.
    if let Some((carried, started)) = pending {
        push(&mut directives, &section, &carried, started);
    }
    directives
}

/// Whether `text` has a `[section]` header, ignoring case.
///
/// The three plugins here all read `.conf` files, an extension that names nothing in
/// particular, so each one gates on the section that identifies *its* kind of file
/// before it records anything. A `.conf` belonging to something else must produce no
/// grants at all rather than a plausible-looking wrong one.
#[must_use]
pub fn has_section(text: &str, section: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .is_some_and(|name| name.trim().eq_ignore_ascii_case(section))
    })
}

/// Split a directive value the way systemd splits an argument list.
///
/// Whitespace separates, `"` and `'` quote a run containing whitespace, and `\` escapes
/// the next character. Good enough for the directives these plugins read, all of which
/// are path lists and command lines.
#[must_use]
pub fn words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut started = false;

    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match (character, quote) {
            ('\\', _) => escaped = true,
            (c, Some(open)) if c == open => quote = None,
            (c, None) if c == '"' || c == '\'' => {
                quote = Some(c);
                // A quoted empty string is still a word.
                started = true;
            }
            (c, None) if c.is_whitespace() => {
                if started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (c, _) => current.push(c),
        }
    }
    if started || !current.is_empty() {
        words.push(current);
    }
    words
}

/// Whether `value` holds a `%` specifier, and therefore names nothing until systemd
/// expands it.
///
/// `%%` is a literal percent and does not count. This is the same judgement pm's own
/// source analysis makes about a string literal holding `%` or `{`: a path assembled at
/// run time is not a path, and recording it would put a file that never existed into the
/// profile.
#[must_use]
pub fn is_templated(value: &str) -> bool {
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '%' {
            continue;
        }
        if characters.peek() == Some(&'%') {
            characters.next();
            continue;
        }
        return true;
    }
    false
}

/// Strip the prefix characters systemd allows in front of a path or a command line.
///
/// `-` ignore failure, `@` pass a different `argv[0]`, `:` do not expand specifiers,
/// `+` `!` `!!` run with elevated privileges. All of them decorate the value; none of
/// them is part of the path.
#[must_use]
pub fn undecorate(value: &str) -> &str {
    value.trim_start_matches(['-', '@', ':', '+', '!'])
}

/// The absolute path `value` names, or `None`.
///
/// `None` for a relative path, which names nothing that survives leaving the build
/// machine, and for a templated one - see [`is_templated`].
#[must_use]
pub fn absolute_path(value: &str) -> Option<&str> {
    let path = undecorate(value.trim());
    (path.starts_with('/') && !is_templated(path)).then_some(path)
}

/// Record one `Key=Value` line, if that is what it is.
fn push(directives: &mut Vec<Directive>, section: &str, line: &str, number: usize) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    directives.push(Directive {
        section: section.to_owned(),
        key: key.trim().to_owned(),
        value: value.trim().to_owned(),
        line: number,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_comments_and_blank_lines() {
        let parsed = parse(
            "# a comment\n; another\n\n[Service]\nType=simple\nExecStart=/usr/bin/foo\n\n\
             [Install]\nWantedBy=multi-user.target\n",
        );
        assert_eq!(parsed.len(), 3);
        assert!(parsed[1].is("service", "execstart"));
        assert_eq!(parsed[1].value, "/usr/bin/foo");
        assert_eq!(parsed[1].line, 6);
        assert_eq!(parsed[2].section, "Install");
    }

    #[test]
    fn a_trailing_backslash_folds_the_next_line_in() {
        let parsed = parse("[Service]\nReadWritePaths=/a \\\n  /b \\\n  /c\nType=simple\n");
        assert_eq!(parsed[0].value, "/a /b /c");
        assert_eq!(
            parsed[0].line, 2,
            "evidence points at where the value started"
        );
        assert_eq!(
            parsed[1].key, "Type",
            "the fold ends where the backslashes do"
        );
    }

    #[test]
    fn a_value_may_hold_an_equals_sign() {
        let parsed = parse("[Service]\nEnvironment=FOO=bar=baz\n");
        assert_eq!(parsed[0].value, "FOO=bar=baz");
    }

    #[test]
    fn words_honour_quoting_and_escapes() {
        assert_eq!(words("/a /b"), ["/a", "/b"]);
        assert_eq!(words(r#""/with space" /b"#), ["/with space", "/b"]);
        assert_eq!(words(r"/with\ space /b"), ["/with space", "/b"]);
        assert_eq!(words("   "), Vec::<String>::new());
    }

    #[test]
    fn a_specifier_makes_a_value_name_nothing() {
        assert!(is_templated("/var/lib/%i"));
        assert!(is_templated("%t/socket"));
        assert!(!is_templated("/var/lib/foo"));
        assert!(!is_templated("/100%%-literal"), "%% is an escaped percent");
        assert_eq!(absolute_path("/etc/foo.conf"), Some("/etc/foo.conf"));
        assert_eq!(absolute_path("-/etc/default/foo"), Some("/etc/default/foo"));
        assert_eq!(absolute_path("relative/path"), None);
        assert_eq!(absolute_path("/run/%i.pid"), None);
    }

    #[test]
    fn gating_on_a_section_is_case_insensitive_and_exact() {
        assert!(has_section("[transfer]\nx=y\n", "Transfer"));
        assert!(!has_section("[TransferList]\nx=y\n", "Transfer"));
        assert!(!has_section("# [Transfer] in a comment\n", "Transfer"));
    }
}
