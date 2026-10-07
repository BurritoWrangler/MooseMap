# Tauri app icons

These binary icons are **generated** from `assets/moosemap.svg`, not committed.
Tauri's bundler needs PNG/ICNS/ICO sizes referenced in `tauri.conf.json`.

Generate them with the Tauri CLI (installed by `scripts/setup-kali.sh`):

```bash
# from the repo root
cargo tauri icon assets/moosemap.svg --output src-tauri/icons
```

This produces `32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`,
`icon.ico`, and the Android/iOS sets. The `make app-build` target runs this for
you before bundling.

If you don't have the Tauri CLI, any PNG at the sizes listed in
`tauri.conf.json` works; `rsvg-convert`/ImageMagick can produce them from the
SVG.
