# Le Phu Duc — Personal Site

Source code of Le Phu Duc's personal site: writeups and research on reverse engineering, CTFs and security.

Built with [Hugo](https://gohugo.io). Posts are written in Markdown. No Node.js required.

## Requirements

- [Hugo **extended**](https://gohugo.io/installation/) 0.146 or newer (built and tested with 0.166.0)

```bash
# macOS
brew install hugo
# Windows
winget install Hugo.Hugo.Extended
# Linux: download the "extended" release from https://github.com/gohugoio/hugo/releases
```

## Getting started

```bash
hugo server -D        # dev server at http://localhost:1313 (-D also shows drafts)
hugo --minify         # build the static site into public/
```

## Project structure

```
hugo.toml                   # site name, tagline, portrait, recent-post count, menu, code theme
content/                    # all text content, in Markdown
├─ _index.md                #   home page introduction
├─ about.md                 #   /about/
├─ achievements.md          #   /achievements/
└─ posts/
   ├─ _index.md             #   /posts/ page title and subtitle
   └─ <post-name>.md        #   one file per post → /posts/<post-name>/
layouts/                    # HTML templates
├─ baseof.html              #   shell for every page: <head>, masthead, nav, footer
├─ home.html                #   home page: intro, portrait, recent posts
├─ list.html                #   /posts/: all posts grouped by year
├─ single.html              #   simple pages (About, Achievements, …)
├─ posts/single.html        #   blog post: byline in the right margin
├─ _markup/render-heading.html  # adds the § link to headings
└─ partials/                #   reusable pieces
   ├─ masthead.html         #     ornament + title + subtitle
   ├─ ornament.html         #     crescent-moon SVG
   ├─ byline.html           #     post date / author / tags
   ├─ post-list.html        #     list of posts (optionally by year)
   ├─ post-entry.html       #     one row in a post list
   ├─ nav.html              #     bottom menu
   └─ footer.html           #     copyright line
archetypes/posts.md         # template used by `hugo new posts/…`
assets/css/main.css         # colors, fonts and layout
static/js/site.js           # Copy buttons on code blocks
static/images/              # images, served at /images/...
```

## Editing content

| To change… | Edit |
|---|---|
| Home page introduction | `content/_index.md` |
| Site name, tagline, portrait, number of recent posts | `[params]` in `hugo.toml` |
| Menu links | `[menus]` in `hugo.toml` |
| About / Achievements | `content/about.md`, `content/achievements.md` |
| Add a page (e.g. Projects) | create `content/projects.md`, then add it to `[menus]` |
| How every post looks | `layouts/posts/single.html` |
| Header / footer on every page | `layouts/partials/masthead.html`, `layouts/partials/footer.html` |
| Colors and fonts | top of `assets/css/main.css` |
| Code highlighting theme | `[markup.highlight] style` in `hugo.toml` |

To show a portrait on the home page, put the image in `static/images/` and set
`portrait = '/images/portrait.png'` in `hugo.toml`.

## Writing a post

```bash
hugo new posts/<post-name>.md
```

This creates `content/posts/<post-name>.md` from `archetypes/posts.md`. The file name becomes the URL
(`/posts/<post-name>/`), so use lowercase letters, numbers and hyphens. Then:

1. Edit the frontmatter (`title`, `subtitle`, `category`, `tags`).
2. Write the content in Markdown. Add the language after the opening ``` to get syntax highlighting.
3. Set `draft: false` (or delete the line) to publish.

| Field | Description |
|---|---|
| `title` | Post title |
| `subtitle` | Short summary shown under the title and in lists |
| `date` | Publish date |
| `category` | `writeup` (default) or `blogs` |
| `tags` | List of tags, e.g. `["reverse", "crypto"]` |
| `draft` | `true` hides the post from the built site |

Images: put files in `static/images/` and reference them as `/images/name.png`

## Deploying

**Vercel or Cloudflare Pages** (works with private repositories):

- Import the GitHub repository.
- Framework preset: **Hugo**. Build command: `hugo --minify`. Output directory: `public`.
- Add the environment variable `HUGO_VERSION` = `0.166.0` so the host uses the same Hugo version.

## Credits

Website built with the assistance of **plebaotrn**.

## License

Copyright (c) 2026 Le Phu Duc. All rights reserved.

The source code of this website is proprietary. See [LICENSE](./LICENSE) for details.