# KELVIN Deployment — Supabase Setup Guide

## 1. Project Initialization & Database Provisioning

1. Log in to the [Supabase Dashboard](https://supabase.com/dashboard) and create a new project:
   - **Organization**: Kelvin Security
   - **Project Name**: `kelvin-production` (or `kelvin-staging`)
   - **Database Password**: Generate a secure, 32-character password.
   - **Region**: Select target enterprise cloud region (e.g. `us-east-1` or `eu-central-1`).

2. Retrieve Connection Strings:
   - Navigate to **Project Settings -> Database**.
   - Copy the direct connection string (Port 5432) or pooled connection string (PgBouncer Port 6543).
   - Ensure SSL Mode is configured to `verify-full`.

---

## 2. Storage Bucket Creation & Security

Navigate to **Storage -> Buckets** in the Supabase Dashboard and provision the required private buckets:

```bash
# Bucket 1: Reports Storage
Name: kelvin-reports-private
Public: False (Disabled)
File size limit: 50 MB
Allowed MIME types: application/pdf, text/html

# Bucket 2: Evidence Storage
Name: kelvin-evidence-private
Public: False (Disabled)
File size limit: 50 MB
Allowed MIME types: application/json, application/octet-stream, text/plain
```

---

## 3. Database Schema Migrations

Run database migrations using the standard `golang-migrate` CLI or automated CI deployment pipeline:

```bash
migrate -path apps/api/db/migrations \
  -database "postgres://postgres:<DB_PASSWORD>@db.<PROJECT_REF>.supabase.co:5432/postgres?sslmode=verify-full" \
  up
```

Verify that all tables, indexes, and constraints are applied cleanly without warnings.
