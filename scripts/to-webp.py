"""Convert PNG/JPG images in content/ to WebP and update the Markdown links.

PNG becomes lossless WebP (no quality loss, good for screenshots).
JPG becomes WebP at quality 90.
The original file is moved to backup/ (ignored by git), keeping its folder path.

Usage (from the repo root):
    python scripts/to-webp.py            # convert, keep originals in backup/
    python scripts/to-webp.py --dry-run  # only show what would change
    python scripts/to-webp.py --delete   # convert and delete originals
"""

import re
import sys
from pathlib import Path

from PIL import Image

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "content"
BACKUP = REPO / "backup"
DRY = "--dry-run" in sys.argv
DELETE = "--delete" in sys.argv


def convert(src: Path) -> Path:
    dst = src.with_suffix(".webp")
    with Image.open(src) as im:
        if src.suffix.lower() == ".png":
            im.save(dst, "WEBP", lossless=True, method=6)
        else:
            im.convert("RGB").save(dst, "WEBP", quality=90, method=6)
    return dst


def main() -> None:
    before = after = 0
    for src in sorted(ROOT.rglob("*")):
        if src.suffix.lower() not in (".png", ".jpg", ".jpeg"):
            continue
        size = src.stat().st_size
        before += size
        if DRY:
            print(f"would convert {src.relative_to(ROOT)} ({size // 1024} KB)")
            continue
        dst = convert(src)
        after += dst.stat().st_size

        # Point links in the Markdown files of the same folder to the new file
        link = re.compile(r"(\]\(|src=[\"'])" + re.escape(src.name) + r"(?=[)\s\"'])")
        for md in src.parent.glob("*.md"):
            text = md.read_text(encoding="utf-8")
            new = link.sub(lambda m: m.group(1) + dst.name, text)
            if new != text:
                md.write_text(new, encoding="utf-8", newline="")
        if DELETE:
            src.unlink()
        else:
            keep = BACKUP / src.relative_to(ROOT)
            keep.parent.mkdir(parents=True, exist_ok=True)
            src.replace(keep)
        print(f"{src.relative_to(ROOT)}: {size // 1024} KB -> {dst.stat().st_size // 1024} KB")

    if before and not DRY:
        print(f"\ntotal: {before // 1024} KB -> {after // 1024} KB ({100 - after * 100 // before}% smaller)")
        if not DELETE:
            print(f"originals kept in {BACKUP.relative_to(REPO)}/")


if __name__ == "__main__":
    main()
