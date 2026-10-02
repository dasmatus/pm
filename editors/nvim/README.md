# pm.nvim

Minimal Neovim support for `pm` `.package` files.

## lazy.nvim

```lua
{
  dir = "/home/runner/work/pm/pm/editors/nvim",
  ft = { "pm" },
  config = function()
    require("pm").setup()
  end,
}
```

## Notes

- `setup()` maps the `pm` filetype to the `starlark` Tree-sitter parser.
- PM-specific highlight tweaks are also shipped under `after/queries/starlark/` so they apply while reusing the upstream parser.
- If `nvim-treesitter` is installed and does not already know `starlark`, the plugin registers the parser from `<https://github.com/tree-sitter-grammars/tree-sitter-starlark>` at `a453dbf3ba433db0e5ec621a38a7e59d72e4dc69`.
- `pm-lsp` must be on `$PATH` for LSP support.
