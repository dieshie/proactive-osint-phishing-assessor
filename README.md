# Proactive User Vulnerability Assessment Method Against Targeted Phishing Based on OSINT Data

## Overview
This repository contains a specialized OSINT (Open Source Intelligence) framework designed to proactively assess individual vulnerability to targeted phishing (Spear Phishing) attacks. By automating the collection and semantic analysis of publicly available data from multiple social platforms, the utility calculates a quantitative Risk Index (0-100) and identifies specific attack vectors.

This project was developed as part of a Bachelor's Thesis to demonstrate the integration of automated data scraping, Natural Language Processing (NLP), and heuristic risk modeling in the field of Cybersecurity.

## Key Features
- **Multi-Source Data Aggregation**: Modular scrapers for LinkedIn, GitHub, and Facebook.
- **Cross-Platform Identity Resolution**: A normalization engine that merges disparate data points into a unified digital profile.
- **NLP-Powered Analysis**: Utilizes `spaCy` (Named Entity Recognition) to identify corporate entities, technologies, and behavioral markers.
- **Heuristic Scoring Model**: A mathematical framework that evaluates 5 distinct risk vectors:
    - High-Value Target (HVT) Status
    - Technical Infrastructure Exposure
    - Social Trust Anchors (Family/Connections)
    - Corporate/BEC (Business Email Compromise) Vectors
    - Behavioral/Emotional Triggers
- **Automated Reporting**: Generates human-readable terminal reports and machine-readable JSON exports for security auditing.

## Technical Architecture
The system follows a modular, decoupled architecture to ensure scalability and maintainability:

1. **Extraction Layer (`scrapers/`)**: Leveraging `Playwright` and `BeautifulSoup4` for resilient, asynchronous data retrieval.
2. **Normalization Layer (`core/normalizer.py`)**: Consolidates raw data, removes duplicates, and prepares unified text for semantic processing.
3. **Analysis Layer (`core/analyzer.py`)**: The "Heuristic Engine" that executes NLP tasks and calculates the final Vulnerability Index.
4. **Presentation Layer (`core/reporter.py`)**: Utilizes the `Rich` library for professional CLI visualization and data serialization.

## Methodology
The risk assessment logic is based on a weighted sum of identified artifacts. Each artifact is assigned a weight based on its utility in a real-world phishing scenario (e.g., a CEO position carries a higher risk weight than a general location mention). The final score is categorized into four severity levels:
- **Low (0-25)**: Minimal public footprint.
- **Medium (26-50)**: Standard professional exposure.
- **High (51-75)**: Significant data available for personalized social engineering.
- **Critical (76-100)**: Immediate risk; full attack vector available.

## Prerequisites
- Python 3.8+
- Playwright (with Chromium browser)
- spaCy (en_core_web_sm model)

## Installation and Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/dieshie/proactive-osint-phishing-assessor.git](https://github.com/dieshie/proactive-osint-phishing-assessor.git)
   cd proactive-osint-phishing-assessor
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
4. Install Playwright browsers:
   ```bash
   playwright install chromium
5. Download the NLP model:
   ```bash
   python -m spacy download en_core_web_sm

## Usage

Configure your target list in data/targets.json:
   ```bash
{
    "targets": [
        {
            "id": "Target_01",
            "last_name": "Surname",
            "social_links": {
                "github": "[https://github.com/username](https://github.com/username)",
                "facebook": "[https://www.facebook.com/username](https://www.facebook.com/username)"
            }
        }
    ]
}
```
Execute the scanning pipeline:
   ```bash
python main.py
```
## Disclaimer
This tool is for educational and authorized security auditing purposes only. The developer is not responsible for any misuse of this software. Always adhere to the Terms of Service of the platforms being analyzed and local privacy laws.