# site/

Single-page landing site for raysense, deployed to GitHub Pages by
`.github/workflows/pages.yml`. Lives at
[https://rayforcedb.github.io/raysense/](https://rayforcedb.github.io/raysense/)
once the workflow runs (and after the one-time Pages-source step
described below).

## Local preview

Pure static HTML/CSS, no build step. Serve from this directory:

```bash
cd site
python3 -m http.server 8000
# open http://localhost:8000
```

## Layout

```
site/
  index.html              landing page
  style.css               all styles, single file
  assets/
    favicon.svg
    fonts/                Inter, Oswald, JetBrains Mono (woff2, latin)
    img/
      treemap-mockup.svg  PLACEHOLDER, swap with a real dashboard screenshot
```

## Replacing the treemap mockup

The hero shows `assets/img/treemap-mockup.svg`, a stand-in. To replace
with a real dashboard capture:

1. `cargo run -- . --ui` (or `cargo install raysense && raysense . --ui`).
2. Open `http://localhost:7000` in a browser, wait for the treemap to
   settle, take a screenshot at ~1440x960 (so it scales cleanly to the
   720x480 hero slot).
3. Save as `site/assets/img/treemap.png` (or `.gif` for animated).
4. In `index.html`, change the `<img src>` from
   `assets/img/treemap-mockup.svg` to `assets/img/treemap.png` and
   update the `alt` text. Drop or keep the SVG mockup as a fallback.

## One-time GitHub Pages setup

The deploy workflow assumes Pages is configured to use GitHub Actions
as its source. In repo Settings -> Pages, set Source to "GitHub
Actions". After the first successful workflow run, the site URL
appears in the deploy step's output.

## Editing copy

`index.html` is the only page; the canonical wording mirrors the
project [README](../README.md). When the README changes, sync the
hero / problem / quality-signal / what-you-get sections so the two
stay aligned. The README is the source of truth.
