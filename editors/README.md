# Editor integrations

This directory contains editor support for `pm` `.package` files.

- `tree-sitter-pm/` layers PM-specific Tree-sitter queries over upstream `tree-sitter-starlark` pinned at `a453dbf3ba433db0e5ec621a38a7e59d72e4dc69`.
- `zed/` is a Zed extension that maps `.package` files to the Starlark grammar and starts `pm-lsp`.
- `nvim/` is a Neovim plugin with filetype detection, Tree-sitter wiring, query overlays, and `pm-lsp` setup.
