# CyberSecAI

CyberSecAI is an AI-assisted cybersecurity analysis platform that combines Nmap network scanning, deterministic security analysis, structured reporting, and optional AI-assisted interpretation.

The project is designed as a portfolio-quality software engineering project demonstrating modular architecture, defensive cybersecurity analysis, automated testing, and responsible AI integration.

## Current Features

- Nmap integration for authorized security assessments
- Service and version detection
- Scan-target validation
- Nmap output parsing
- Evidence-based security analysis
- Structured security rules for common network services
- Severity classification
- Standardized security findings
- JSON security reports
- Markdown security reports
- Optional AI-assisted security analysis
- Mock AI provider for local testing
- OpenAI provider abstraction
- Automated test suite with pytest

## Architecture

```text
                         CyberSecAI
                              |
                         Command Line
                              |
                              v
                     +----------------+
                     |    Scanner     |
                     |     Nmap       |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     |     Parser     |
                     |  Nmap Output   |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     |    Analyzer    |
                     | Structured     |
                     | Security Rules |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     |    Summary     |
                     |   Findings     |
                     +-------+--------+
                             |
                  +----------+----------+
                  |                     |
                  v                     v
          +---------------+     +---------------+
          | AI Workflow   |     |   Reporting   |
          |   Optional    |     |   JSON / MD   |
          +-------+-------+     +---------------+
                  |
                  v
          +---------------+
          | AI Providers  |
          | OpenAI / Mock |
          +---------------+