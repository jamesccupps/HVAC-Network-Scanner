# Screenshots

This directory is referenced by README.md for project screenshots, and the
website (site/, published by .github/workflows/pages.yml) shows every PNG in
it. All are taken against the simulated site, never a real building:

```
python tools/sim_site.py
python tools/gui_demo.py docs/screenshots/main-window.png devices --select=Tracer --geometry=1500x860+40+20 --dpi=96
python tools/gui_demo.py docs/screenshots/points.png points --sort=-Status --geometry=1500x860+40+20 --dpi=96
python tools/gui_demo.py docs/screenshots/trends-schedules-alarms.png meta --geometry=1500x860+40+20 --dpi=96
```

Drop PNG or JPG images here — the README can then link to them with
stable repo-relative paths like:

```markdown
![HVAC Network Scanner](docs/screenshots/main-window.png)
```

The old README pointed at a
`https://private-user-images.githubusercontent.com/...?jwt=...` URL. Those
are signed with short-lived JWTs that expire and show a 404 to anyone
other than the original uploader — not suitable for a public repo.
