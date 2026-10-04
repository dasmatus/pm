# Editor integrations

This directory contains editor support for `pm` recipes. Recipes are Rhai `.rhai` files; Starlark `.package` files are deprecated but still supported until pm stops loading them.

- `zed/` is a Zed extension that maps `.rhai` files to the [`tree-sitter-rhai`](https://github.com/elkowar/tree-sitter-rhai) grammar pinned at `4ac7384d487ffcb54e746ef1569585a749370c5b`, `.package` files to the Starlark grammar, and starts `pm-lsp` for both.
- `nvim/` is a Neovim plugin with filetype detection, Tree-sitter wiring, query overlays, and `pm-lsp` setup.
- `tree-sitter-pm/` layers PM-specific Tree-sitter queries over upstream `tree-sitter-starlark` pinned at `a453dbf3ba433db0e5ec621a38a7e59d72e4dc69`, for the deprecated `.package` files.
