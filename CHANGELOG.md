# Changelog

This project follows Keep a Changelog and Semantic Versioning. During `0.x`, a
minor release may contain breaking schema or policy changes; patch releases do
not intentionally break documented contracts.

## Unreleased

## 0.1.5 - 2026-08-16

### Added

- Complete-package inventory with bounded file, archive, and symlink handling.
- Package security rules `STO-PKG-200` through `STO-PKG-210`.
- SARIF 2.1.0 output, expiring suppressions, and baseline generation.
- Rule-set version contract `2026.1`.
- Provider-neutral HTTP red-team target.
- 500-case deterministic calibration fixture corpus and family metrics.

### Changed

- Minimum Python version lowered to 3.11.
- Behavioral success verdict renamed from `assured` to `passed_scope`.
- Reworked the README around the product workflow, trust model, CLI, Python API,
  operating bounds, and measured performance.
