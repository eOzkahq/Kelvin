# PostgreSQL 16 Multi-AZ Persistence Tier

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "kelvin/${var.environment}/database/master"
  description = "Managed master credentials for KELVIN PostgreSQL database"

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials_val" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.admin_username
    password = random_password.db_password.result
    engine   = "postgres"
    port     = 5432
    database = var.database_name
  })
}

resource "aws_db_subnet_group" "kelvin" {
  name        = "kelvin-${var.environment}-db-subnets"
  description = "Subnet group for KELVIN Zone 4 database tier"
  subnet_ids  = var.subnet_ids

  tags = {
    Name        = "kelvin-${var.environment}-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_db_parameter_group" "kelvin_pg16" {
  name        = "kelvin-${var.environment}-pg16-params"
  family      = "postgres16"
  description = "Hardened parameter group for KELVIN PostgreSQL 16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_db_instance" "primary" {
  identifier                  = "kelvin-${var.environment}-postgres"
  engine                      = "postgres"
  engine_version              = "16.2"
  instance_class              = var.instance_class
  allocated_storage           = var.allocated_storage
  max_allocated_storage       = var.max_allocated_storage
  storage_type                = "gp3"
  storage_encrypted           = true
  multi_az                    = var.multi_az
  publicly_accessible         = false
  deletion_protection         = var.deletion_protection
  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false

  db_name  = var.database_name
  username = var.admin_username
  password = random_password.db_password.result

  db_subnet_group_name   = aws_db_subnet_group.kelvin.name
  vpc_security_group_ids = var.security_group_ids
  parameter_group_name   = aws_db_parameter_group.kelvin_pg16.name

  backup_retention_period   = 35
  backup_window             = "03:00-04:00"
  maintenance_window        = "Sun:04:30-Sun:05:30"
  copy_tags_to_snapshot     = true
  final_snapshot_identifier = "kelvin-${var.environment}-postgres-final"
  skip_final_snapshot       = var.environment == "dev" ? true : false

  tags = {
    Name        = "kelvin-${var.environment}-db-primary"
    Environment = var.environment
  }
}
