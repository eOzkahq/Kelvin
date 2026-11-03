output "alb_security_group_id" {
  description = "Security group ID for Application Load Balancer"
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "Security group ID for Go API and App tier"
  value       = aws_security_group.app.id
}

output "worker_security_group_id" {
  description = "Security group ID for Worker fleet"
  value       = aws_security_group.worker.id
}

output "sandbox_security_group_id" {
  description = "Security group ID for Scanner execution sandbox"
  value       = aws_security_group.sandbox.id
}

output "redis_security_group_id" {
  description = "Security group ID for Redis broker"
  value       = aws_security_group.redis.id
}

output "db_security_group_id" {
  description = "Security group ID for PostgreSQL database"
  value       = aws_security_group.db.id
}

output "api_role_arn" {
  description = "IAM role ARN for API service"
  value       = aws_iam_role.api_role.arn
}

output "worker_role_arn" {
  description = "IAM role ARN for Worker service"
  value       = aws_iam_role.worker_role.arn
}

output "scanner_role_arn" {
  description = "IAM role ARN for Scanner tasks"
  value       = aws_iam_role.scanner_role.arn
}
