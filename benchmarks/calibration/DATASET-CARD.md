# SkillTrustOps static-security calibration fixtures

This dataset contains 500 deterministic, Apache-2.0 synthetic fixtures: 250
positive and 250 benign cases across ten rule families. Labels follow fixture
construction and are useful for regression testing.

They are **not independently reviewed labels** and must not be represented as
real-world accuracy evidence. Every record has `review_status`, primary and
secondary annotator fields, and an adjudication field. Publication-grade accuracy
claims require two independent human annotations and adjudication of every
disagreement.

Run `python benchmarks/calibration/generate_dataset.py` and then
`python benchmarks/calibration/evaluate.py`. The evaluator reports TP, FP, FN,
TN, precision, recall, F1, false-positive rate, and Wilson intervals by family.

`independent-review.csv` is the blinded second-review queue. A reviewer who did
not author the fixtures records a label, evidence span, identity, and confidence.
An adjudicator then updates `cases.jsonl` for disagreements. Until all 500 rows
are complete, public results remain regression metrics rather than accuracy
claims.
