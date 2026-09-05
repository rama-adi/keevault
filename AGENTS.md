<!--VITE PLUS START-->

# Using Vite+, the Unified Toolchain for the Web

This project is using Vite+, a unified toolchain built on top of Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task. Vite+ wraps runtime management, package management, and frontend tooling in a single global CLI called `vp`. Vite+ is distinct from Vite, and it invokes Vite through `vp dev` and `vp build`. Run `vp help` to print a list of commands and `vp <command> --help` for information about a specific command.

Docs are local at `node_modules/vite-plus/docs` or online at https://viteplus.dev/guide/.

## Built-in Commands vs Scripts

`vp <name>` runs a built-in command. `vp run <name>` runs a `package.json` script or a `vite.config.ts` task. Scripts cannot overwrite built-ins, so `vp dev` and `vp run dev` may do different things. Check `package.json` and `vite.config.ts` first, and run `vp run <name>` when the project defines a script or task with that name.

## Tool Versions

Run `vp toolchain` to show versions and relationships in the active Vite+
release. Add a tool name to select part of the graph. For example, run
`vp toolchain vite`. Use `--global` to ignore the local `vite-plus` package. Use
`vp why <package>` to show the package-manager dependency graph.

## Review Checklist

- [ ] Run `vp install` after pulling remote changes and before getting started.
- [ ] Run `vp check` and `vp test` to format, lint, type check and test changes.
- [ ] Check if there are `vite.config.ts` tasks or `package.json` scripts necessary for validation, run via `vp run <script>`.
- [ ] If setup, runtime, or package-manager behavior looks wrong, run `vp env doctor` and include its output when asking for help.

<!--VITE PLUS END-->

## TanStack Start app conventions

These apply to every TanStack Start app in this repo.

**A page is not a component.** Components are reusable blocks; a page is a single
destination. Anything reachable at a URL lives in `src/routes` next to its route
definition, never in `src/components`. This holds regardless of where the page
renders — SPA-only pages and server-rendered pages that rehydrate on the client
are still pages.

**The routes folder should be scannable as a tree.** Express nesting with real
directories and a real `page-name.tsx` for the leaf. Router dot-notation
(`example.foo` for `example/foo`) is supported but flattens the hierarchy into
filenames, so don't use it.

**Adopt before authoring.** shadcn/ui is the default component source. When a
component exists in the shadcn registry, install it (`shadcn add`) and use it.
Write a custom component only once the registry has been checked and has nothing
that fits.

**Styled components derive from shadcn primitives.** An app keeps its shadcn
primitives in `src/components/ui` and its styled, product-facing components in a
separate directory built on top of them. Add a product-facing component by
copying the corresponding primitive out of `src/components/ui` (installing it
from shadcn first if it is missing) and styling the copy to match the ones
already there — not by starting from scratch, and not by restyling the
primitives in place, which every other consumer depends on.
