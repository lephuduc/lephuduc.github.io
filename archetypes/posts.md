---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
subtitle: "One short sentence, shown under the title and in the post list."
date: {{ .Date }}
category: writeup        # or: blogs
tags: ["reverse"]
draft: true              # set to false (or remove) to publish
---

## First section

Write the post in Markdown.
