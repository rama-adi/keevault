# KeeVault marketing and documentation

A TanStack Start app with Tailwind CSS and Fumadocs. The landing page explains KeeVault's human-approved secret delivery. User documentation lives in `content/docs` and is served at `/docs`.

From the repository root:

```sh
vp install
vp run dev:marketing
```

The app runs at `http://localhost:3001`. Use `vp run keevault-marketing#build` to build it and `vp run keevault-marketing#preview` to preview the build locally. The preview command is a local preview server, not a production deployment configuration.

## Editing documentation

Add MDX files to `content/docs` with `title` and `description` frontmatter. Update `content/docs/meta.json` to place pages in the sidebar. Fumadocs builds the page tree, table of contents, and `/api/search` index from the same content. Links between pages use `/docs/page-name`.

Routes live in `src/routes` using real directories. The shared Fumadocs provider and metadata live in `src/routes/__root.tsx`. `src/styles/app.css` contains Tailwind, Fumadocs styles, and the marketing design tokens.

Run `vp check` and `vp test` from the root for the repository checks. This app's build compiles every documentation page.
