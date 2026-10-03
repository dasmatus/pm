# pm.nvim

Minimal Neovim support for `pm` recipes: Rhai `.rhai` files, and deprecated
Starlark `.package` files.

## lazy.nvim

```lua
{
  dir = "/path/to/pm/editors/nvim",
  ft = { "rhai", "pm" },
  config = function()
    require("pm").setup()
  end,
}
```

## Notes

- `.rhai` files get the `rhai` filetype. If `nvim-treesitter` is installed and does not already know `rhai`, the plugin registers the parser from `<https://github.com/elkowar/tree-sitter-rhai>` at `4ac7384d487ffcb54e746ef1569585a749370c5b`; run `:TSInstall rhai` once. Highlight queries, including pm's builtins, ship under `queries/rhai/`.
- `.package` files are deprecated Starlark recipes (`pm migrate` converts them). `setup()` maps their `pm` filetype to the `starlark` Tree-sitter parser, registering it from `<https://github.com/tree-sitter-grammars/tree-sitter-starlark>` at `a453dbf3ba433db0e5ec621a38a7e59d72e4dc69` if needed, and pm-specific tweaks ship under `after/queries/starlark/`.
- `pm-lsp` must be on `$PATH` for LSP support. It serves both filetypes, and flags `.package` files as deprecated.
