vim.filetype.add({
    extension = {
        rhai = "rhai",
        -- Deprecated Starlark recipes; `pm migrate` converts them to `.rhai`.
        package = "pm",
    },
})
