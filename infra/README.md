# KELVIN Infrastructure as Code (IaC)

This directory contains the production-grade Terraform / OpenTofu configurations defining all cloud infrastructure, network topology, container compute, persistence tiers, and security policies for KELVIN.

---

## Directory Structure

```text
infra/
├── terraform/
│   ├── modules/
│   │   ├── networking/   # VPC, Zone 0-4 subnets, IGW, NAT Gateways, Route Tables
│   │   ├── security/     # Zone Security Groups & Least-Privilege IAM Roles
│   │   ├── database/     # Multi-AZ PostgreSQL 16 RDS, Parameter Groups, PgBouncer
│   │   ├── broker/       # Redis Sentinel / Valkey Queue Broker (ElastiCache)
│   │   ├── storage/      # KMS-encrypted S3 buckets for Evidence & Reports, Lifecycles
│   │   ├── compute/      # ECS Fargate Cluster, Task Definitions, Auto-scaling
│   │   └── ingress/      # Public Application Load Balancer, Target Groups, TLS 1.3
│   └── environments/
│       ├── dev/          # Development Environment (10.100.0.0/16, Single-AZ)
│       ├── staging/      # Staging Environment (10.200.0.0/16, Multi-AZ)
│       └── prod/         # Production Environment (10.0.0.0/16, 3-AZ High Availability)
└── README.md
```

---

## Key Principles & Security Controls

1. **Zero Hardcoded Secrets:**
   - All credentials, DB passwords, and sensitive keys are managed dynamically via AWS Secrets Manager and KMS.
   - Example configuration files (`terraform.tfvars.example`) provide non-sensitive parameter blueprints.
2. **Strict Network Segmentation:**
   - Compute resources run in private/isolated subnets.
   - Scanner sandboxes (Zone 3) have zero routes or security group allowances to the database or internal VPC resources.
3. **Environment Separation:**
   - Dev, Staging, and Production share identical modular code with isolated state backends, distinct VPC CIDRs, and independent encryption keys.
4. **Controlled Lifecycle & Destruction:**
   - Production database and buckets enforce deletion protection and lifecycle retention locks.
   - See `docs/operations/INFRASTRUCTURE_AS_CODE_GUIDE.md` for provisioning, rollback, and destruction procedures.
