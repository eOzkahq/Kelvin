output "vpc_id" {
  description = "Staging VPC ID"
  value       = module.networking.vpc_id
}

output "alb_dns_name" {
  description = "Staging Application Load Balancer DNS Name"
  value       = module.ingress.alb_dns_name
}

output "database_endpoint" {
  description = "Staging PostgreSQL Endpoint"
  value       = module.database.db_endpoint
}

output "redis_endpoint" {
  description = "Staging Redis Primary Endpoint"
  value       = module.broker.redis_primary_endpoint
}

output "evidence_bucket" {
  description = "Staging Evidence Storage S3 Bucket"
  value       = module.storage.evidence_bucket_name
}

output "reports_bucket" {
  description = "Staging Reports Storage S3 Bucket"
  value       = module.storage.reports_bucket_name
}
