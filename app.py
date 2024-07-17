from flask import Flask, jsonify, render_template, request
from zapv2 import ZAPv2
import time
import random
from datetime import datetime, timedelta

app = Flask(__name__)

# ZAP configuration
zap_api_key = 'YOUR_ZAP_API_KEY'
zap_proxy = 'http://localhost:8080'

zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_proxy, 'https': zap_proxy})

# In-memory database to store scan history
scan_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.json['url']
    try:
        # Perform ZAP scan
        scan_id = zap.spider.scan(url)
        while int(zap.spider.status(scan_id)) < 100:
            time.sleep(1)
        
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)
        
        alerts = zap.core.alerts()
        
        # Process and categorize alerts
        vulnerabilities = process_alerts(alerts)
        
        # Add to scan history
        scan_history.append({
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities
        })
        
        return jsonify({
            'success': True,
            'data': generate_dashboard_data(url, vulnerabilities)
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def process_alerts(alerts):
    vulnerability_types = {
        'sql_injection': 'SQL Injection',
        'xss': 'Cross-Site Scripting (XSS)',
        'csrf': 'Cross-Site Request Forgery (CSRF)',
        'broken_auth': 'Broken Authentication',
        'sensitive_data': 'Sensitive Data Exposure',
        'other': 'Other'
    }
    
    vulnerabilities = {vtype: [] for vtype in vulnerability_types.values()}
    
    for alert in alerts:
        vtype = 'Other'
        for key, value in vulnerability_types.items():
            if key in alert['name'].lower():
                vtype = value
                break
        vulnerabilities[vtype].append({
            'name': alert['name'],
            'url': alert['url'],
            'risk': alert['risk'],
            'confidence': alert['confidence']
        })
    
    return vulnerabilities

def generate_dashboard_data(url, vulnerabilities):
    total_vulnerabilities = sum(len(v) for v in vulnerabilities.values())
    
    severity_distribution = {
        'High': sum(1 for v in vulnerabilities.values() for alert in v if alert['risk'] == 'High'),
        'Medium': sum(1 for v in vulnerabilities.values() for alert in v if alert['risk'] == 'Medium'),
        'Low': sum(1 for v in vulnerabilities.values() for alert in v if alert['risk'] == 'Low'),
        'Informational': sum(1 for v in vulnerabilities.values() for alert in v if alert['risk'] == 'Informational')
    }
    
    vulnerability_types = {k: len(v) for k, v in vulnerabilities.items()}
    
    # Generate some mock data for time-based charts
    dates = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30, 0, -1)]
    
    return {
        'url': url,
        'totalVulnerabilities': total_vulnerabilities,
        'severityDistribution': severity_distribution,
        'vulnerabilityTypes': vulnerability_types,
        'vulnerabilityTrend': {
            'dates': dates,
            'counts': [random.randint(total_vulnerabilities - 10, total_vulnerabilities + 10) for _ in dates]
        },
        'timeToFix': {
            'dates': dates,
            'averageTimes': [random.uniform(1, 10) for _ in dates]
        },
        'topVulnerablePages': [
            {'url': v['url'], 'count': random.randint(1, 5)} 
            for v in vulnerabilities['Other'][:5]  # Just an example, you might want to process this differently
        ],
        'recentScans': [
            {
                'url': scan['url'],
                'timestamp': scan['timestamp'],
                'totalVulnerabilities': sum(len(v) for v in scan['vulnerabilities'].values())
            } 
            for scan in scan_history[-5:]
        ]
    }

if __name__ == '__main__':
    app.run(debug=True)