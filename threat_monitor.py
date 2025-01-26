# File: threat_monitor.py

import requests
import json
import sqlite3
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# Configuration for threat intelligence feeds and alerting
CONFIG = {
    "feeds": [
        {"name": "Feed1", "url": "https://example.com/threat-feed1.json", "type": "json"},
        {"name": "Feed2", "url": "https://example.com/threat-feed2.rss", "type": "rss"},
    ],
    "alert_threshold": "critical",
    "smtp": {
        "server": "smtp.example.com",
        "port": 587,
        "username": "your-email@example.com",
        "password": "your-password",
        "recipient": "recipient@example.com"
    }
}

# Initialize SQLite database for threat logging
def init_db():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT,
            indicator TEXT,
            severity TEXT,
            description TEXT,
            timestamp DATETIME
        )
    """)
    conn.commit()
    conn.close()

# Fetch data from a feed
def fetch_feed(feed):
    try:
        response = requests.get(feed["url"], timeout=10)
        response.raise_for_status()
        return response.json() if feed["type"] == "json" else response.text
    except Exception as e:
        print(f"Error fetching feed {feed['name']}: {e}")
        return None

# Parse and process the feed data
def process_feed(feed_name, data, feed_type):
    threats = []
    if feed_type == "json":
        for item in data.get("threats", []):
            threats.append({
                "feed_name": feed_name,
                "indicator": item.get("indicator"),
                "severity": item.get("severity"),
                "description": item.get("description"),
                "timestamp": datetime.now()
            })
    # Add support for RSS/XML parsing here if needed
    return threats

# Save threats to the database
def save_to_db(threats):
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    for threat in threats:
        cursor.execute("""
            INSERT INTO threats (feed_name, indicator, severity, description, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (threat["feed_name"], threat["indicator"], threat["severity"], threat["description"], threat["timestamp"]))
    conn.commit()
    conn.close()

# Alert for critical threats
def send_alert(threats):
    smtp_config = CONFIG["smtp"]
    critical_threats = [t for t in threats if t["severity"].lower() == CONFIG["alert_threshold"]]
    if not critical_threats:
        return

    subject = "Critical Threat Alert!"
    body = "\n\n".join([f"{t['indicator']} - {t['description']} (Severity: {t['severity']})" for t in critical_threats])
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = smtp_config["username"]
    message["To"] = smtp_config["recipient"]

    try:
        with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as server:
            server.starttls()
            server.login(smtp_config["username"], smtp_config["password"])
            server.sendmail(smtp_config["username"], smtp_config["recipient"], message.as_string())
            print("Alert sent successfully.")
    except Exception as e:
        print(f"Error sending alert: {e}")

# Main function
def main():
    init_db()
    for feed in CONFIG["feeds"]:
        data = fetch_feed(feed)
        if data:
            threats = process_feed(feed["name"], data, feed["type"])
            save_to_db(threats)
            send_alert(threats)
    print("Threat monitoring completed.")

if __name__ == "__main__":
    main()
