output "vpc_id" {
  description = "Production VPC ID"
  value       = module.networking.vpc_id
}

output "alb_dns_name" {
  description = "Production Application Load Balancer DNS Name"
  value       = module.ingress.alb_dns_name
}

output "database_endpoint" {
  description = "Production PostgreSQL Endpoint"
  value       = module.database.db_endpoint
}

output "redis_endpoint" {
  description = "Production Redis Primary Endpoint"
  value       = module.broker.redis_primary_endpoint
}

output "evidence_bucket" {
  description = "Production Evidence Storage S3 Bucket"
  value       = module.storage.evidence_bucket_name
}

output "reports_bucket" {
  description = "Production Reports Storage S3 Bucket"
  value       = module.storage.reports_bucket_name
}
