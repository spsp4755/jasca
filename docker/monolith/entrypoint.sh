#!/bin/bash
set -e

# Data directories
PG_DATA="/var/lib/postgresql/data"
REDIS_DATA="/var/lib/redis"

echo "Initializing JASCA Monolithic Container..."
echo "--- ENTRYPOINT V4 (UPGRADE SAFE) ---"

DB_PASSWORD="${DB_PASSWORD:-}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
CORS_ORIGIN="${CORS_ORIGIN:-http://localhost:3000}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/app/trivy-db}"

if [ -z "${JWT_SECRET:-}" ]; then
    echo "Error: JWT_SECRET must be provided with docker run -e JWT_SECRET=..."
    exit 1
fi

if [ -z "$DB_PASSWORD" ]; then
    echo "Error: DB_PASSWORD must be provided with docker run -e DB_PASSWORD=..."
    exit 1
fi

DATABASE_URL="${DATABASE_URL:-postgresql://jasca:${DB_PASSWORD}@127.0.0.1:5432/jasca?sslmode=disable}"

export DB_PASSWORD DATABASE_URL REDIS_URL CORS_ORIGIN TRIVY_CACHE_DIR JWT_SECRET

# Ensure permissions
chown -R postgres:postgres "$PG_DATA"
chown -R redis:redis "$REDIS_DATA"
chmod 0700 "$PG_DATA"

FRESH_INSTALL=0

# Initialize Postgres if empty
if [ -z "$(ls -A "$PG_DATA")" ]; then
    echo "This is a fresh install. Initializing Database..."
    FRESH_INSTALL=1
    
    # Init DB with Korean locale
    su - postgres -c "/usr/lib/postgresql/14/bin/initdb --locale=ko_KR.UTF-8 -D $PG_DATA"
    
    # Configure Postgres to allow local connections
    echo "host all all 127.0.0.1/32 md5" >> "$PG_DATA/pg_hba.conf"
    echo "listen_addresses='*'" >> "$PG_DATA/postgresql.conf"
    
    echo "Database initialization complete."
fi

echo "Starting temporary Postgres for migration check..."
su - postgres -c "/usr/lib/postgresql/14/bin/pg_ctl -D $PG_DATA -w start"

if [ "$FRESH_INSTALL" = "1" ]; then
    echo "Creating 'jasca' user and database..."
    su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='jasca'\" | grep -q 1 || psql -c \"CREATE USER jasca WITH PASSWORD '$DB_PASSWORD';\""
    su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='jasca'\" | grep -q 1 || psql -c \"CREATE DATABASE jasca OWNER jasca;\""
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE jasca TO jasca;\""
    su - postgres -c "psql -d jasca -c \"GRANT ALL ON SCHEMA public TO jasca;\""
fi

echo "Waiting for Postgres to be ready..."
until su - postgres -c "pg_isready -h localhost -p 5432"; do
    echo "Postgres is unavailable - sleeping"
    sleep 1
done

echo "Running Prisma migrations..."
export CHECKPOINT_DISABLE=1

echo "Checking Prisma version..."
/app/node_modules/.bin/prisma --version
/app/node_modules/.bin/prisma migrate deploy --schema=/app/apps/api/prisma/schema.prisma

if [ "$FRESH_INSTALL" = "1" ]; then
    echo "Running database seed..."
    node /app/apps/api/prisma/seed.js
else
    echo "Existing database detected. Skipping seed; migrations only."
fi

echo "Stopping temporary Postgres..."
su - postgres -c "/usr/lib/postgresql/14/bin/pg_ctl -D $PG_DATA -m fast -w stop"

# Execute the passed command (usually supervisord)
exec "$@"
