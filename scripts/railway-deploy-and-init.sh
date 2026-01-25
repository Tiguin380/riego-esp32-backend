#!/usr/bin/env bash
set -e

# Script to deploy repo to Railway and run /api/init
# Requirements:
#  - RAILWAY_API_KEY env var
#  - RAILWAY_PROJECT_ID (optional)
# Usage: RAILWAY_API_KEY=... RAILWAY_PROJECT_ID=... ./scripts/railway-deploy-and-init.sh

if [ -z "$RAILWAY_API_KEY" ]; then
  echo "RAILWAY_API_KEY is required"
  exit 1
fi

npm i -g @railway/cli
railway login --apiKey "$RAILWAY_API_KEY"
if [ -n "$RAILWAY_PROJECT_ID" ]; then
  railway link --projectId "$RAILWAY_PROJECT_ID" || true
fi
railway up --detach

echo "Deployed to Railway. If your service URL is available, call /api/init to initialize DB, or set AUTO_DB_INIT=true in Railway variables to have it run automatically on startup."
