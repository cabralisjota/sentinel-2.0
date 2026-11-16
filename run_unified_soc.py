"""Run the permanently registered Unified Access SOC locally on port 5000."""
import json
import os
from pathlib import Path

base = Path(__file__).resolve().parent
os.chdir(base)
os.environ['ENABLE_ACCESS_SOC'] = '1'
settings_file = base / '.access_soc/local_settings.json'
if settings_file.is_file():
    settings = json.loads(settings_file.read_text())
    os.environ.setdefault('ACCESS_LAB_DB', settings['access_lab_db'])
ids_token = base / '.sentinel_ids_token'
if ids_token.is_file():
    os.environ.setdefault('SENTINEL_INGEST_TOKEN', ids_token.read_text().strip())

from app import app

if __name__ == '__main__':
    print('\nUnified Access SOC v2: http://127.0.0.1:5000/access-monitor\n'
          'Sign in with your existing Access Lab password. CTRL+C stops this server.\n', flush=True)
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
