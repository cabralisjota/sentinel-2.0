"""Local, read-only Sentinel Access Lab integration."""

import os
import sys
import sqlite3
from pathlib import Path
from datetime import datetime

from flask import (
    request, abort, jsonify, render_template_string
)

DB = Path(
    os.environ.get(
        "ACCESS_LAB_DB",
        str(
            Path.home() /
            ".sentinel-access-lab" /
            "access.db"
        )
    )
).expanduser()

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
 content="width=device-width,initial-scale=1">
<title>Sentinel 2.0 | Unified Access SOC</title>
<style>
:root {color-scheme:dark}
body {
 margin:0;
 background:#080e19;
 color:#dce8fa;
 font:14px/1.5 system-ui;
}
main {
 max-width:1100px;
 margin:auto;
 padding:20px;
}
a {color:#00dffa}
h1 {font-size:25px}
small,.muted {color:#8fa7c2}
.grid {
 display:grid;
 grid-template-columns:
 repeat(auto-fit,minmax(160px,1fr));
 gap:12px;
}
.card {
 background:#101d30;
 border:1px solid #29405a;
 border-radius:10px;
 padding:16px;
 margin:14px 0;
}
.value {
 font-size:28px;
 font-weight:700;
}
.scroll {overflow-x:auto}
table {
 width:100%;
 border-collapse:collapse;
 min-width:640px;
}
th,td {
 text-align:left;
 border-bottom:1px solid #29405a;
 padding:8px;
}
th {
 color:#93acc7;
 font-size:11px;
}
.high,.critical {color:#ff839a}
.medium {color:#ffd17a}
.low {color:#72e8b4}
</style>
</head>
<body>
<main>
<p>
<a href="/">← Sentinel 2.0</a> ·
<a href="http://127.0.0.1:5002/">
Access Lab controls</a>
</p>

<h1>▣ Unified Access SOC</h1>
<p class="muted">
Network demo + simulated RFID events
· Read-only · Local only
</p>

<div class="card">
{% if connected %}
● Access Lab database connected
{% else %}
○ Access Lab database not found.
Start Access Lab first.
{% endif %}
</div>

<div class="grid">
<div class="card">
<small>Combined events</small>
<div class="value">{{ events|length }}</div>
</div>
<div class="card">
<small>RFID events</small>
<div class="value">{{ physical }}</div>
</div>
<div class="card">
<small>Open cases</small>
<div class="value">{{ open_cases }}</div>
</div>
</div>

<div class="card">
<h2>Access investigations</h2>
<div class="scroll">
<table>
<tr>
<th>ID</th><th>RULE</th><th>BADGE</th>
<th>DOOR</th><th>SEVERITY</th><th>STATUS</th>
</tr>
{% for c in cases %}
<tr>
<td>{{ c.id }}</td>
<td>{{ c.rule }}</td>
<td>{{ c.badge_id }}</td>
<td>{{ c.door_id }}</td>
<td class="{{ c.severity }}">{{ c.severity }}</td>
<td>{{ c.status }}</td>
</tr>
{% else %}
<tr>
<td colspan="6">No investigations yet</td>
</tr>
{% endfor %}
</table>
</div>
</div>

<div class="card">
<h2>Combined event timeline</h2>
<div class="scroll">
<table>
<tr>
<th>TIME</th><th>SOURCE</th><th>EVENT</th>
<th>SUBJECT</th><th>LOCATION</th><th>SEVERITY</th>
</tr>
{% for e in events %}
<tr>
<td>{{ e.time }}</td>
<td>{{ e.source }}</td>
<td>{{ e.event }}</td>
<td>{{ e.subject }}</td>
<td>{{ e.location }}</td>
<td class="{{ e.severity }}">{{ e.severity }}</td>
</tr>
{% else %}
<tr>
<td colspan="6">No events yet</td>
</tr>
{% endfor %}
</table>
</div>
</div>

<p class="muted">
Refresh the page to see new events.
No workplace systems are connected.
</p>
</main>
</body>
</html>
"""

def register_access_soc(app):
    # Disabled by default, including on public hosting.
    if os.environ.get("ENABLE_ACCESS_SOC") != "1":
        return

    def local_only():
        if request.remote_addr not in (
            "127.0.0.1", "::1"
        ):
            abort(403)

    def query(sql):
        if not DB.is_file():
            return []

        uri = DB.resolve().as_uri() + "?mode=ro"

        with sqlite3.connect(
            uri, uri=True, timeout=3
        ) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            return [
                dict(row)
                for row in con.execute(sql)
            ]

    def feed():
        mod = sys.modules.get(app.import_name)
        network = getattr(mod, "events", [])
        lock = getattr(mod, "lock", None)

        if lock:
            with lock:
                sample = list(network[:70])
        else:
            sample = list(network[:70])

        combined = [
            dict(
                time=str(e.get("timestamp", "")),
                source="Network demo",
                event=e.get("type", "Event"),
                subject=e.get("ip", ""),
                location=e.get("country", ""),
                severity=e.get("severity", "low")
            )
            for e in sample
            if isinstance(e, dict)
        ]

        rows = query(
            "SELECT ts,badge_id,door_id,result,kind "
            "FROM events ORDER BY id DESC LIMIT 70"
        )

        for e in rows:
            combined.append(
                dict(
                    time=datetime.fromtimestamp(
                        e["ts"]
                    ).isoformat(timespec="seconds"),
                    source="RFID simulation",
                    event=e["result"],
                    subject=e["badge_id"],
                    location=e["door_id"],
                    severity=(
                        "high"
                        if e["kind"] == "forced"
                        else "medium"
                        if e["result"] == "DENIED"
                        else "low"
                    )
                )
            )

        cases = query(
            "SELECT id,rule,severity,badge_id,"
            "door_id,status FROM cases "
            "ORDER BY id DESC LIMIT 40"
        )

        combined.sort(
            key=lambda e: e["time"],
            reverse=True
        )

        return combined[:140], cases

    @app.get("/api/unified-events")
    def unified_events():
        local_only()

        try:
            events, cases = feed()
        except (sqlite3.Error, OSError, ValueError):
            return jsonify(
                error="Could not read Access Lab database"
            ), 503

        return jsonify(
            events=events,
            cases=cases,
            access_connected=DB.is_file()
        )

    @app.get("/access-monitor")
    def access_monitor():
        local_only()

        try:
            events, cases = feed()
        except (sqlite3.Error, OSError, ValueError):
            return (
                "Could not read Access Lab database",
                503
            )

        return render_template_string(
            PAGE,
            events=events,
            cases=cases,
            connected=DB.is_file(),
            physical=sum(
                e["source"] == "RFID simulation"
                for e in events
            ),
            open_cases=sum(
                c["status"] != "resolved"
                for c in cases
            )
        )

    @app.after_request
    def add_access_navigation(response):
        if (
            request.path != "/"
            or response.status_code != 200
            or response.mimetype != "text/html"
        ):
            return response

        html = response.get_data(as_text=True)

        if 'href="/access-monitor"' in html:
            return response

        link = (
            '<a href="/access-monitor" '
            'style="display:block;padding:12px;'
            'color:#00dffa;font-weight:700">'
            '▣ Unified Access SOC</a>'
        )

        if "</aside>" in html:
            html = html.replace(
                "</aside>",
                link + "</aside>",
                1
            )
        elif "</body>" in html:
            floating = (
                '<div style="position:fixed;'
                'right:12px;bottom:12px;'
                'background:#101d30;'
                'border:1px solid #00dffa;'
                'z-index:999">'
                + link + '</div>'
            )
            html = html.replace(
                "</body>",
                floating + "</body>",
                1
            )
        else:
            return response

        response.set_data(html)
        return response
