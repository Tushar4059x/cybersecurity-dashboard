# Advanced Vulnerability Scanner Dashboard

## Overview

The Advanced Vulnerability Scanner Dashboard is a web-based application that provides a comprehensive interface for scanning websites for vulnerabilities using the OWASP Zed Attack Proxy (ZAP). It offers real-time scanning capabilities and presents the results in an intuitive, visually appealing dashboard.

## Features

- Web-based interface for easy vulnerability scanning
- Real-time scanning using OWASP ZAP
- Interactive dashboard with various charts and statistics
- Vulnerability trend analysis
- Severity distribution visualization
- Breakdown of vulnerability types
- Time-to-fix tracking
- List of top vulnerable pages
- Recent scan history

## Technologies Used

- Backend: Python with Flask
- Frontend: HTML, JavaScript, Tailwind CSS
- Charting: Chart.js
- Vulnerability Scanning: OWASP ZAP (Zed Attack Proxy)

## Prerequisites

- Python 3.7+
- OWASP ZAP
- pip (Python package manager)

## Installation

1. Clone the repository:
    git clone https://github.com/Tushar4059x/cybersecurity-dashboard

2. Install the required Python packages:
    pip install flask python-owasp-zap-v2.4

3. Install and set up OWASP ZAP:
- Download ZAP from [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)
- Follow the installation instructions for your operating system

## Configuration

1. Open `app.py` and replace `'YOUR_ZAP_API_KEY'` with your actual ZAP API key.
2. Ensure ZAP is running and accessible at `http://localhost:8080` (default setting).

## Usage

1. Start the Flask application:
    python app.py

2. Open a web browser and navigate to `http://localhost:5000`

3. Enter the URL of the website you want to scan in the input field.

4. Click the "Scan" button to initiate the vulnerability scan.

5. View the results in the interactive dashboard.

## Dashboard Sections

- **Total Vulnerabilities**: Overall count of discovered vulnerabilities
- **Scanned URL**: The URL of the website that was scanned
- **Last Scan**: Timestamp of the most recent scan
- **Severity Distribution**: Pie chart showing the distribution of vulnerability severities
- **Vulnerability Types**: Bar chart displaying the types of vulnerabilities found
- **Vulnerability Trend**: Line chart showing the trend of vulnerabilities over time
- **Time to Fix Trend**: Line chart tracking the average time to fix vulnerabilities
- **Top Vulnerable Pages**: List of pages with the most vulnerabilities
- **Recent Scans**: History of recent scans performed

## Caution

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan a website before using this tool.

## Contributing

Contributions to improve the Advanced Vulnerability Scanner Dashboard are welcome. Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## Disclaimer

This tool is provided as-is, without any warranties. The developers are not responsible for any misuse or damage caused by this tool. Use responsibly and ethically.
