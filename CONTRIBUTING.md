# Contributing to Phishing URL Analyzer

Thanks for wanting to help. This is a small project so keep it simple.

## Getting set up

Requires Python 3.11 or newer.

git clone https://github.com/LemuelOwusuAnsah/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python app.py

The dev server runs at http://localhost:5000

## Project layout

app.py has the Flask app and all twelve heuristics.
templates/index.html is the dashboard.
static/app.js handles fetch and render.
static/style.css has the SOC theme.
tests/ has pytest tests for the scoring functions and the endpoint.
.github/workflows/ci.yml runs lint and tests on every push.

## Style

Two spaces, LF line endings, UTF-8. See .editorconfig.
Ruff for Python linting. Run ruff check . before pushing.
Keep heuristics as pure functions so they are testable.
Findings follow the shape {title, severity, detail}.

## Adding a heuristic

Add a pure function in app.py that takes parsed URL components and returns an optional finding.
Add a pytest test in tests/test_heuristics.py.
Add an API test in tests/test_api.py if the heuristic should be exercised end-to-end.
Wrap it into the analyze endpoint with a severity weight.

## Before pushing

ruff check .
pytest -v

If both pass, push. GitHub Actions runs the same checks.

## Commits

Short, plain English, present tense.

Add homoglyph detection for cyrillic characters
Fix raw IP host regex
Update risk score weights

## Reporting issues

Open a GitHub issue with what you expected, what happened, the URL that triggered it if safe to share, and your browser and OS.
