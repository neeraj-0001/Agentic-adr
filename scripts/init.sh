#!/bin/bash
set -e

echo '=== Agentic ADR System Initialization ==='

echo 'Installing dependencies...'
pip install -r requirements.txt

echo 'Creating config directory...'
mkdir -p config

echo 'Checking ClickHouse connection...'
python3 -c '
from src.storage.clickhouse_store import AgenticTraceStore
try:
    store = AgenticTraceStore()
    print('ClickHouse connection successful')
except Exception as e:
    print(f'Warning: ClickHouse not available: {e}')
'

echo ''
echo '=== Initialization Complete ==='
echo ''
echo 'To start the ADR server:'
echo '  python -m src.api.server'
echo ''
echo 'To start with Docker:'
echo '  cd docker && docker-compose up -d'
echo ''
echo 'API Endpoints:'
echo '  GET  /health           - Health check'
echo '  POST /v1/initialize    - Initialize with framework'
echo '  POST /v1/spans         - Ingest telemetry spans'
echo '  GET  /v1/traces/{id}   - Get trace by ID'
echo '  GET  /v1/sessions/{id} - Get session summary'
echo '  POST /v1/scan/input    - Scan input for threats'
echo '  POST /v1/scan/output   - Scan output for threats'
echo '  GET  /v1/threats       - Query high threat events'
echo '  POST /v1/killswitch/trigger - Trigger containment'
echo '  GET  /v1/contained     - List contained agents'