# Le Phu Duc - Personal Site

Personal site of Le Phu Duc. Writeups and notes on reverse engineering, CTFs and security.

Built with [Hugo](https://gohugo.io). Posts are written in Markdown. No Node.js needed.

## Setup

Install Hugo extended, version 0.146 or newer (tested with 0.166.0).

```bash
winget install Hugo.Hugo.Extended     # Windows
brew install hugo                     # macOS
```

Run the site:

```bash
hugo server -D      # local site at http://localhost:1313, -D also shows drafts
hugo --minify       # build the site into public/
```

## Folders

```
hugo.toml                       # site name, tagline, avatar, menu
content/
├─ _index.md                    #   home page text
├─ about.md                     #   /about/
├─ achievements.md              #   /achievements/
└─ posts/
   ├─ _index.md                 #   /posts/ title and subtitle
   └─ <post-name>/              #   one folder per post, link /posts/<post-name>/
      ├─ index.md               #     the post
      └─ *.png, *.jpg           #     images of the post
layouts/                        # HTML templates
├─ baseof.html                  #   frame of every page: head, header, menu, footer
├─ home.html                    #   home page: intro, avatar, recent posts
├─ list.html                    #   /posts/: all posts by year
├─ single.html                  #   simple pages (About, Achievements)
├─ posts/single.html            #   a post, with date and tags in the right margin
├─ shortcodes/
│  ├─ note.html                 #   numbered note in the right column
│  └─ side.html                 #   note without number, for references
├─ _markup/
│  ├─ render-heading.html       #   adds the § link to headings
│  └─ render-image.html         #   makes WebP copies, lazy loading
└─ partials/                    #   small reusable pieces
   ├─ masthead.html             #     ornament, title, subtitle
   ├─ ornament.html             #     vine ornament at the top
   ├─ fleuron.html              #     small ornament at the end of posts and in footer
   ├─ dropcap.html              #     big decorated first letter
   ├─ byline.html               #     post date, author, tags
   ├─ tags.html                 #     category and tags of a post
   ├─ post-list.html            #     list of posts
   ├─ post-entry.html           #     one row in the list
   ├─ nav.html                  #     menu
   └─ footer.html               #     copyright line
archetypes/posts.md             # template for `hugo new posts/...`
scripts/to-webp.py              # convert post images to WebP (see Images in a post)
assets/
├─ css/                         #   joined into one file when building
│  ├─ fonts.css                 #     font files and fallback fonts
│  ├─ main.css                  #     colors, sizes and layout
│  └─ syntax.css                #     code highlighting colors
└─ images/                      #   avatar (Hugo resizes it)
static/
├─ fonts/                       #   font files (Alegreya, Alegreya SC, Inconsolata)
│  └─ floral-capitals/          #     drop cap font, one file per letter A-Z
├─ js/site.js                   #   Copy button on code blocks
└─ images/                      #   other images, served at /images/...
```

## Common changes

| To change | Edit |
|---|---|
| Home page text | `content/_index.md` |
| Site name, tagline, avatar | `[params]` in `hugo.toml` |
| Menu | `[menus]` in `hugo.toml` |
| Colors and sizes | top of `assets/css/main.css` |
| Fonts | `assets/css/fonts.css` and `static/fonts/` |
| Code colors | `assets/css/syntax.css` (make a new one with `hugo gen chromastyles --style=<name>`) |
| Add a page | create `content/<name>.md`, then add it to `[menus]` |

## Write a post

```bash
hugo new posts/<post-name>/index.md
```

The folder name is the link: `/posts/<post-name>/`. Use lowercase letters, numbers and `-` only.

Fields at the top of the post:

| Field | Meaning |
|---|---|
| `title` | Post title |
| `subtitle` | Short line under the title |
| `date` | Publish date |
| `category` | `writeup` or `blogs` |
| `tags` | For example `["reverse", "crypto"]` |
| `draft` | `true` hides the post |
| `dropcap` | `false` turns off the big first letter |

## Images in a post

Put the image in the post folder and use its file name:

```
content/posts/<post-name>/main.png
```

```markdown
![Disassembly of main](main.png)
```

No need to resize. Hugo makes small WebP copies when building. The browser loads only the size it needs, and only when the reader scrolls near the image. Click an image to open the original.

To make the repo lighter, convert the original files to WebP too. This also updates the links in `index.md`:

```bash
python scripts/to-webp.py --dry-run   # show what will change
python scripts/to-webp.py             # convert (needs: pip install pillow)
python scripts/to-webp.py --delete    # convert and delete the originals
```

PNG becomes lossless WebP, so screenshots keep full quality.
Originals are moved to `backup/` (same folder path, not pushed to git). Delete that folder when you no longer need it.

## Notes on the right

In a post, put a note right after the word it explains:

```markdown
It saves these bytes as a rc4 key.{{< note >}}RC4 is a stream cipher.{{< /note >}}
The flag is encrypted.{{< side >}}Reference: [RC4](https://en.wikipedia.org/wiki/RC4){{< /side >}}
```

`note` adds a number, `side` has no number. Links, `code` and images work inside, for example
`{{< side >}}![Stack layout](stack.webp) The stack after the call.{{< /side >}}`. On phones the note shows under the line.

## Deploy

Vercel or Cloudflare Pages:

- Import the GitHub repo.
- Framework: Hugo. Build command: `hugo --minify`. Output folder: `public`.
- Add env variable `HUGO_VERSION` = `0.166.0`.

## Credits

Website built with the help of @plebaotrn.

## License

Copyright (c) 2026 Le Phu Duc. All rights reserved. See [LICENSE](./LICENSE).
