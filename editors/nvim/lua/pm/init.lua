local M = {}

-- Recipes are Rhai. `.package` files are deprecated Starlark recipes, still
-- highlighted with the Starlark parser until pm stops loading them.
local parsers_wanted = {
    rhai = {
        url = "https://github.com/elkowar/tree-sitter-rhai",
        revision = "4ac7384d487ffcb54e746ef1569585a749370c5b",
    },
    starlark = {
        url = "https://github.com/tree-sitter-grammars/tree-sitter-starlark",
        revision = "a453dbf3ba433db0e5ec621a38a7e59d72e4dc69",
    },
}

local function register_parser()
    if not (vim.treesitter and vim.treesitter.language and vim.treesitter.language.register) then
        return
    end

    pcall(vim.treesitter.language.register, "starlark", "pm")

    local ok, parsers = pcall(require, "nvim-treesitter.parsers")
    if not ok then
        return
    end

    local configs = parsers.get_parser_configs()
    for name, source in pairs(parsers_wanted) do
        if not configs[name] then
            configs[name] = {
                install_info = {
                    url = source.url,
                    branch = "master",
                    revision = source.revision,
                    files = { "src/parser.c" },
                },
                filetype = name,
            }
        end
    end
end

local function lsp_config()
    return {
        cmd = { "pm-lsp" },
        filetypes = { "rhai", "pm" },
        root_markers = { ".git" },
    }
end

local function fallback_root(bufnr)
    if vim.fs and vim.fs.root then
        return vim.fs.root(bufnr, { ".git" }) or vim.fn.getcwd()
    end

    return vim.fn.getcwd()
end

local function enable_lsp()
    local config = lsp_config()

    if vim.lsp and vim.lsp.config and vim.lsp.enable then
        vim.lsp.config("pm_lsp", config)
        vim.lsp.enable("pm_lsp")
        return
    end

    local group = vim.api.nvim_create_augroup("pm_lsp", { clear = true })
    vim.api.nvim_create_autocmd("FileType", {
        group = group,
        pattern = { "rhai", "pm" },
        callback = function(args)
            if vim.b[args.buf].pm_lsp_started then
                return
            end

            vim.b[args.buf].pm_lsp_started = true
            vim.lsp.start({
                name = "pm-lsp",
                cmd = config.cmd,
                root_dir = fallback_root(args.buf),
            })
        end,
    })
end

function M.setup(_opts)
    register_parser()
    enable_lsp()
end

return M
