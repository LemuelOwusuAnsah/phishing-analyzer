# Phishing URL Analyzer

A heuristic phishing URL analyzer with a SOC-style dashboard. Paste a URL, get a risk score from 0 to 100 and a breakdown of what triggered it.

## Overview

Paste any URL and the analyzer runs twelve heuristics against it: homoglyph tricks, Levenshtein distance to popular brand names, Shannon entropy in the hostname, suspicious TLDs, raw IP hosts, embedded credentials, URL length, subdomain depth, and phishing keywords. It returns a weighted risk score, a verdict (safe, low, medium, or high), and a per-finding breakdown with severity.

Built with Flask on the backend and vanilla JavaScript on the frontend. No framework, no build step. Runs on Python 3.11 or newer.

## Stack

Flask 3.0 for the API and template rendering. requests for any outbound checks. python-whois for domain age lookups. tldextract for reliable TLD parsing. Vanilla JavaScript and hand-written CSS for the dashboard.

## Heuristics

Homoglyph detection catches lookalike characters like the digit 1 for the letter l, or the Cyrillic а for Latin a.

Levenshtein distance to popular brand names catches typosquats like paypa1, arnazon, or micr0soft.

Shannon entropy of the hostname catches randomized strings like xj3k9q2p.tk.

Suspicious TLD list catches .zip, .tk, .ml, .top, .xyz, and other low-reputation extensions.

Raw IP host catches URLs that bypass DNS entirely, like http://192.168.1.1/login.

Embedded credentials catch URLs with @ in the authority, like http://paypal.com@evil.tk/.

URL length, subdomain count, hyphen count, and keyword scan round out the twelve.

Each finding carries a severity weight. The total is normalized to 0-100.

## Getting started

git clone https://github.com/LemuelOwusuAnsah/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py

Open http://localhost:5000 in your browser.

## Project layout

app.py contains the Flask app, all heuristics, and the analyze endpoint.
templates/index.html is the dashboard.
static/app.js handles the fetch and render logic.
static/style.css is the dark SOC-style theme with scanline effect.
tests/ contains pytest tests for the scoring functions and the endpoint.
.github/workflows/ci.yml runs tests and lint on every push.

## API

POST /api/analyze with JSON body {"url": "https://example.com"}

Returns JSON with fields: url, score (0-100), verdict (safe, low, medium, high), findings (array of {id, label, severity, detail}).

## Roadmap

Shipped: twelve heuristics, SOC dashboard, weighted scoring, sample URLs.

Planned: Cloudflare Workers deployment, whitelist of known-good domains, historical scan log.

## License

MIT. See LICENSE.
