# Actor Tactic Timeline scripts

`tactic_timeline.py` — pulls a threat actor's ATT&CK attack-pattern
observations from the Mallory API, enriches them with MITRE tactics (and
optionally source publication dates), buckets them into time periods, and
reports how the actor's tactic mix evolves.

```bash
uv pip install --system --upgrade malloryapi
export MALLORY_API_KEY=sk-...

python tactic_timeline.py "ShinyHunters" --period month --format markdown
```

Outputs JSON by default; pass `--format markdown` for a human-readable report,
or `--format html` for a self-contained, interactive technique × time heatmap.
The HTML inlines the Geist webfont from `../assets/fonts_css.txt` as base64
`@font-face`, so it makes no external requests and is CSP-safe to publish with
the Artifact tool. See the skill's SKILL.md for full options.
