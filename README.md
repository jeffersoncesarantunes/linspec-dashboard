# LinSpec Dashboard

Web dashboard to receive and display LinSpec kernel hardening scan reports.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-Python](https://img.shields.io/badge/Language-Python-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Framework-Flask](https://img.shields.io/badge/Framework-Flask-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00A86B?style=flat-square)](#-roadmap)
[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/linspec-dashboard/ci.yml?style=flat-square&logo=github&label=CI)](https://github.com/jeffersoncesarantunes/linspec-dashboard/actions/workflows/ci.yml)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Security%20Dashboard-8A2BE2?style=flat-square)](docs/ARCHITECTURE.md)

## Overview

Collects scan reports via REST API, stores them in SQLite, and displays aggregate statistics and per-scan details.

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

### Generate an API key

Visit `/admin/setup` to create the first API key for submitting scans.

## API

### Submit a scan report

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '{
    "hostname": "server01",
    "kernel": "6.8.0",
    "os": "Linux",
    "checks": [
      {"check": "aslr", "category": "memory", "status": "PASS", "message": ""},
      {"check": "kptr_restrict", "category": "kernel", "status": "VULN", "message": "kptr_restrict=0"}
    ]
  }'
```

### View a raw scan

```
GET /api/scan/<id>/raw
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | HTTP port |
| `SECRET_KEY` | auto | Flask session secret |
| `LINSPEC_DB` | `data.db` | SQLite database path |
| `LINSPEC_DEBUG` | `false` | Enable Flask debug mode |
| `LINSPEC_RATE_LIMIT` | `60` | Max requests per minute per IP |

## Production

Use the bundled `start.sh` with gunicorn:

```bash
./start.sh
```

**Never** run with `LINSPEC_DEBUG=true` in production.

## Tests

```bash
pip install pytest
python -m pytest tests/
```

## License

MIT
