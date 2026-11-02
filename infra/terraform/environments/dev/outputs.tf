output "vpc_id" {
  description = "Dev VPC ID"
  value       = module.networking.vpc_id
}

output "alb_dns_name" {
  description = "Dev Application Load Balancer DNS Name"
  value       = module.ingress.alb_dns_name
}

output "database_endpoint" {
  description = "Dev PostgreSQL Endpoint"
  value       = module.database.db_endpoint
}

output "redis_endpoint" {
  description = "Dev Redis Primary Endpoint"
  value       = module.broker.redis_primary_endpoint
}

output "evidence_bucket" {
  description = "Dev Evidence Storage S3 Bucket"
  value       = module.storage.evidence_bucket_name
}

output "reports_bucket" {
  description = "Dev Reports Storage S3 Bucket"
  value       = module.storage.reports_bucket_name
}
