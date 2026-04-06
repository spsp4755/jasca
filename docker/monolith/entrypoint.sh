#!/bin/bash
set -euo pipefail

# Data directories
PG_DATA="/var/lib/postgresql/data"
REDIS_DATA="/var/lib/redis"
PRISMA_SCHEMA="/app/apps/api/prisma/schema.prisma"
DATABASE_URL_DEFAULT="postgresql://jasca:jasca_secret@127.0.0.1:5432/jasca?sslmode=disable"

echo "Initializing JASCA Monolithic Container..."
echo "--- ENTRYPOINT V3 (UPGRADE SAFE) ---"

# Ensure permissions
chown -R postgres:postgres "$PG_DATA"
chown -R redis:redis "$REDIS_DATA"
chmod 0700 "$PG_DATA"

start_temp_postgres() {
    echo "Starting temporary Postgres for setup..."
    su - postgres -c "/usr/lib/postgresql/14/bin/pg_ctl -D $PG_DATA -w start"
}

stop_temp_postgres() {
    echo "Stopping temporary Postgres..."
    su - postgres -c "/usr/lib/postgresql/14/bin/pg_ctl -D $PG_DATA -m fast -w stop"
}

wait_for_postgres() {
    echo "Waiting for Postgres to be ready..."
    until su - postgres -c "pg_isready -h 127.0.0.1 -p 5432"; do
        echo "Postgres is unavailable - sleeping"
        sleep 1
    done
}

run_fallback_migration() {
    echo "Prisma CLI is unavailable. Applying fallback schema migration for ScanResult metadata..."
    PGPASSWORD=jasca_secret psql -h 127.0.0.1 -U jasca -d jasca -v ON_ERROR_STOP=1 <<'SQL'
ALTER TABLE "ScanResult"
ADD COLUMN IF NOT EXISTS "displayName" TEXT,
ADD COLUMN IF NOT EXISTS "description" TEXT;
SQL
}

find_prisma_bin() {
    local candidate
    for candidate in \
        "/app/node_modules/.bin/prisma" \
        "/app/node_modules/.pnpm/node_modules/.bin/prisma"
    do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

run_migrations() {
    local prisma_bin
    export CHECKPOINT_DISABLE=1
    export DATABASE_URL="${DATABASE_URL:-$DATABASE_URL_DEFAULT}"

    if prisma_bin="$(find_prisma_bin)"; then
        echo "Checking Prisma version..."
        "$prisma_bin" --version
        echo "Running Prisma migrations..."
        "$prisma_bin" migrate deploy --schema="$PRISMA_SCHEMA"
    else
        run_fallback_migration
    fi
}

FRESH_INSTALL=false

# Initialize Postgres if empty
if [ -z "$(ls -A "$PG_DATA" 2>/dev/null)" ]; then
    FRESH_INSTALL=true
    echo "This is a fresh install. Initializing Database..."

    # Init DB with Korean locale
    su - postgres -c "/usr/lib/postgresql/14/bin/initdb --locale=ko_KR.UTF-8 -D $PG_DATA"

    # Configure Postgres to allow local connections
    echo "host all all 127.0.0.1/32 md5" >> "$PG_DATA/pg_hba.conf"
    echo "listen_addresses='*'" >> "$PG_DATA/postgresql.conf"
else
    echo "Existing database detected. Preserving data and applying migrations."
fi

start_temp_postgres
wait_for_postgres

if [ "$FRESH_INSTALL" = true ]; then
    echo "Creating 'jasca' user and database..."
    su - postgres -c "psql -c \"CREATE USER jasca WITH PASSWORD 'jasca_secret';\""
    su - postgres -c "psql -c \"CREATE DATABASE jasca OWNER jasca;\""
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE jasca TO jasca;\""
    su - postgres -c "psql -d jasca -c \"GRANT ALL ON SCHEMA public TO jasca;\""
fi

run_migrations

if [ "$FRESH_INSTALL" = true ]; then
    echo "Running database seed..."
    node /app/apps/api/prisma/seed.js
    echo "Database initialization complete."
else
    echo "Upgrade migration complete. Existing data was preserved."
fi

stop_temp_postgres

# Execute the passed command (usually supervisord)
exec "$@"
