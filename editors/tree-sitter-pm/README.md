# tree-sitter-pm

`pm` build files are plain Starlark with the `.package` extension, so this package intentionally reuses the upstream Starlark grammar instead of defining a new parser.

- Upstream grammar: <https://github.com/tree-sitter-grammars/tree-sitter-starlark>
- Pinned commit: `a453dbf3ba433db0e5ec621a38a7e59d72e4dc69`

## Wiring

1. Install or vendor `tree-sitter-starlark` at the pinned commit.
2. Associate `*.package` with the `pm`/`source.pm` scope in your editor.
3. Point the editor's query search path at this directory's `queries/` folder.

`tree-sitter.json` is metadata for the `.package` file type; parsing still comes from the upstream Starlark grammar.
