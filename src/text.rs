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
