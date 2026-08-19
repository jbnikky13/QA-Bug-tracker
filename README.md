# QA Bug Tracker

Automated website/web-app QA scanner built with Python, Streamlit and Playwright.

## Features

- Crawl internal pages
- HTTP error detection
- JavaScript console error detection
- Failed network request detection
- Broken image detection
- Missing page title detection
- Basic accessibility checks
- Mobile viewport testing
- Screenshots as evidence
- Upload an entire project as one ZIP
- Basic static inspection of uploaded HTML/JS/CSS source
- PDF and DOCX report generation

## Local setup

```bash
pip install -r requirements.txt
playwright install chromium
streamlit run app.py
```

Enter a URL you own or are authorized to test.

## Deployment

For Streamlit Community Cloud, `requirements.txt` and `packages.txt` are included. The first deployment may need Chromium setup depending on the platform image.

## Scope

This is a QA/defect scanner, not an exploit or penetration-testing tool. Only scan applications you own or have permission to test.
