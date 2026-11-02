# AWS Secrets Manager & Cryptographic Key Management

resource "aws_kms_key" "secrets" {
  description             = "KMS Key for KELVIN Secrets Manager (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_kms_alias" "secrets_alias" {
  name          = "alias/kelvin-${var.environment}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# 1. Database App Credentials Secret
resource "random_password" "app_db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_app" {
  name                    = "kelvin/${var.environment}/database/app"
  description             = "Runtime credentials for kelvin_app database role"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "db_app_val" {
  secret_id = aws_secretsmanager_secret.db_app.id
  secret_string = jsonencode({
    username = "kelvin_app"
    password = random_password.app_db_password.result
    engine   = "postgres"
    port     = 5432
  })
}

# 2. Redis Auth Token Secret
resource "random_password" "redis_auth_token" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "kelvin/${var.environment}/redis/auth"
  description             = "Authentication token for Redis queue broker"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "redis_auth_val" {
  secret_id     = aws_secretsmanager_secret.redis_auth.id
  secret_string = random_password.redis_auth_token.result
}

# 3. JWT Signing & Token Secrets
resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "aws_secretsmanager_secret" "jwt_keys" {
  name                    = "kelvin/${var.environment}/auth/jwt"
  description             = "JWT signing secret and session cryptographic keys"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "jwt_keys_val" {
  secret_id = aws_secretsmanager_secret.jwt_keys.id
  secret_string = jsonencode({
    jwt_secret    = random_password.jwt_secret.result
    signing_algo  = "HS256"
    rotation_days = 90
  })
}

# 4. Webhook Signing Secret
resource "random_password" "webhook_signing_secret" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "webhook_signing" {
  name                    = "kelvin/${var.environment}/webhooks/signing"
  description             = "Cryptographic secret for outbound HMAC-SHA256 webhook signing"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "webhook_signing_val" {
  secret_id     = aws_secretsmanager_secret.webhook_signing.id
  secret_string = random_password.webhook_signing_secret.result
}

# 5. Integration Encryption Master Key (Envelope encryption for 3rd-party tokens)
resource "random_password" "integration_envelope_key" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "integration_keys" {
  name                    = "kelvin/${var.environment}/integrations/envelope"
  description             = "Envelope AES-GCM master key for stored Jira/Slack integration credentials"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "integration_keys_val" {
  secret_id     = aws_secretsmanager_secret.integration_keys.id
  secret_string = random_password.integration_envelope_key.result
}
