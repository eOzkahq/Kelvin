output "db_secret_arn" {
  description = "ARN of the application database credentials secret"
  value       = aws_secretsmanager_secret.db_app.arn
}

output "redis_secret_arn" {
  description = "ARN of the Redis authentication secret"
  value       = aws_secretsmanager_secret.redis_auth.arn
}

output "jwt_secret_arn" {
  description = "ARN of the JWT signing keys secret"
  value       = aws_secretsmanager_secret.jwt_keys.arn
}

output "webhook_secret_arn" {
  description = "ARN of the webhook HMAC signing secret"
  value       = aws_secretsmanager_secret.webhook_signing.arn
}

output "kms_key_arn" {
  description = "ARN of the Secrets Manager KMS CMK"
  value       = aws_kms_key.secrets.arn
}
