# SkillTrustOps product video

The final video is `skilltrustops-product-tour.mp4`.

It uses real screens from the local Studio and a genuine Docker sandbox run.
The run intentionally remains `INCONCLUSIVE`: all six behavioral attacks were
resisted, but Docker is development isolation rather than a certifying gVisor
boundary.

Regenerate the narration and video on macOS:

```bash
say -v Samantha -r 175 -f narration.txt -o narration.aiff
../../.venv/bin/python render.py
```
