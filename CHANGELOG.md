# Changelog

All notable changes to Phishing URL Analyzer are listed here. Format follows Keep a Changelog, versions follow SemVer.

## [0.3.0] - 2026-11-08

### Added
- pytest suite with 19 tests across heuristics and API endpoints
- CI workflow running lint and tests on Python 3.11 and 3.12
- requirements-dev.txt with pytest, pytest-flask, ruff
- pytest.ini with testpaths and discovery rules
- README, LICENSE, CONTRIBUTING, CHANGELOG

### Changed
- Disabled GitHub Pages (Flask cannot be statically hosted)

### Fixed
- API tests now match real response shape (uppercase verdict, title-based findings)

## [0.2.0] - 2026-09-27

### Added
- Twelve heuristics: homoglyphs, Levenshtein brand distance, Shannon entropy, suspicious TLDs, raw IP host, embedded credentials, URL length, subdomain depth, hyphen count, keyword scan, HTTPS check, port scan
- Weighted risk score normalized to 0-100
- Verdict levels: SAFE, LOW, MEDIUM, DANGEROUS, HIGH
- SOC-style dashboard with scanline effect and sample URLs

## [0.1.0] - 2026-09-25

### Added
- Initial Flask app with a single endpoint and basic template
- Initial static app.js and style.css
