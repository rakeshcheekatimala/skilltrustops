# Calibration regression summary

## Result

| Measure | Result |
| --- | ---: |
| Cases | 500 |
| Positive fixtures | 250 |
| Benign fixtures | 250 |
| Rule families | 10 |
| True positives | 250 |
| False positives | 0 |
| False negatives | 0 |
| True negatives | 250 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| False-positive rate | 0.000 |

These are construction-derived synthetic regression fixtures. Each family has 25
direct positive examples and 25 direct benign controls. A perfect result means
the implemented rules recognize the fixtures they were designed to recognize.
It does **not** measure performance on independently labeled public skills or
novel attacks.

For each family, the 95% Wilson interval for recall and specificity is
`0.866808–1.0` because each side contains 25 examples. See `results.json` for
per-family confusion matrices and every observed rule.

## Independent review gate

`independent-review.csv` contains all 500 cases with blank reviewer fields. A
second human reviewer must label every case without relying on the construction
label. Disagreements require adjudication. Until that work is complete, public
material must call these *regression metrics*, never *validated accuracy*.
