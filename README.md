# 🔐 CyberSentinel - Security Log Analyzer

CyberSentinel is a Python-based cybersecurity project for analyzing authentication logs and detecting suspicious activity, brute-force attempts, targeted users, and threat patterns.

## 🚀 Features

- Detects brute-force login attempts
- Identifies suspicious IP addresses
- Shows most targeted users
- Lists top IPs by activity
- Generates a JSON security report
- Includes a Flask web dashboard

## 🧰 Technologies

- Python 3
- Flask
- HTML/CSS
- JSON
- Pytest

## 📂 Project Structure

```txt
CyberSentinel/
├── app.py
├── data/
│   └── sample_auth.log
├── src/
│   ├── __init__.py
│   └── analyzer.py
├── static/
│   └── style.css
├── templates/
│   └── dashboard.html
├── tests/
│   └── test_analyzer.py
├── README.md
├── requirements.txt
├── report.json
├── .gitignore
└── LICENSE
```

## ▶️ Run the Web Dashboard

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the Flask dashboard:

```bash
python app.py
```

Open in your browser:

```txt
http://127.0.0.1:5000
```

## 🖥️ Run in Terminal

```bash
python src/analyzer.py data/sample_auth.log --output report.json
```

## 🧪 Run Tests

```bash
pytest
```

## ⚠️ Disclaimer

This project is for educational and defensive security purposes only.

