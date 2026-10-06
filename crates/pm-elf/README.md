# pm-elf

A bounds-checked reader for what an ELF object says about how it links: `PT_INTERP`, `DT_NEEDED`, `DT_RUNPATH` and `DT_RPATH`.

Part of [pm](https://github.com/losos-project/pm). It builds as a member of pm's
cargo workspace, which supplies its version, edition and shared dependency
versions; `CONTRIBUTING.md` at the workspace root describes the layout.

Licensed under the GNU General Public License, version 3 only. See `LICENSE`.
