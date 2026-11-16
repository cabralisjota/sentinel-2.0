# Sentinel 2.0

**Security Monitoring & Visualization | Purple Team Engineering | Full-Stack Development**

Sentinel 2.0 is a Python/Flask cybersecurity dashboard exploring how security events can be collected, classified, visualized, and analyzed. It combines a backend JSON API with an interactive browser interface and a WebGL 3D Earth visualization.

> **Project status:** Portfolio / lab prototype. The current event feed is **simulated**, not a live intrusion detection system or evidence of real attacks.

## Features

- Interactive WebGL 3D Earth visualization with geographic event markers and animated activity routes
- Security-event feed with event type, severity, timestamp, IP, and location
- Charts, dashboard navigation, and responsive interface
- Flask backend and JSON endpoint (`/api/events`)
- Simulated events for repeatable UI and analytics demonstrations
- Browser-based visualization with fallback behavior where WebGL is unavailable

## Technology

| Layer | Tools |
| --- | --- |
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Visualization | WebGL, interactive 3D globe, charts |
| API | JSON over HTTP |
| Development | Termux (Android), Git, GitHub |

## Run locally

```bash
python -m pip install flask
python app.py
```

Open **http://127.0.0.1:5000/** in a browser on the same device.

The 3D globe may require a WebGL-capable browser and an internet connection for externally loaded JavaScript or geographic assets. The default Flask server binds to localhost for development.

## API

`GET /api/events` returns recent simulated events as JSON. Events include fields such as `id`, `time`, `type`, `severity`, `country`, `ip`, `lat`, and `lon`.

The example source addresses use reserved documentation IP ranges and do not represent identified real-world attackers.

## Purple team direction

The goal is to connect **authorized offensive-security lab exercises** with defensive monitoring and detection validation. Planned work includes real log ingestion, controlled attack-lab integration, event correlation, and security automation. These are roadmap items, not currently claimed production capabilities.

## Responsible use

Use only on systems you own or are explicitly authorized to test. This project is intended for learning, defensive analysis, and controlled security exercises.

**Developer:** [@cabralisjota](https://github.com/cabralisjota)
