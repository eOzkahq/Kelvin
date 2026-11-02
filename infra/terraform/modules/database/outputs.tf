output "db_endpoint" {
  description = "Database connection endpoint address"
  value       = aws_db_instance.primary.endpoint
}

output "db_address" {
  description = "Database host address"
  value       = aws_db_instance.primary.address
}

output "db_port" {
  description = "Database port"
  value       = aws_db_instance.primary.port
}

output "secret_arn" {
  description = "Secrets Manager ARN holding master database credentials"
  value       = aws_secretsmanager_secret.db_credentials.arn
}
