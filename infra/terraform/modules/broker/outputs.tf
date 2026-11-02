output "redis_primary_endpoint" {
  description = "Redis primary endpoint address for task queuing"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_port" {
  description = "Redis broker connection port"
  value       = aws_elasticache_replication_group.redis.port
}
