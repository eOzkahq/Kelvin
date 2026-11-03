# Redis Broker & Task Queue (ElastiCache HA Cluster)

resource "aws_elasticache_subnet_group" "redis" {
  name       = "kelvin-${var.environment}-redis-subnets"
  subnet_ids = var.subnet_ids

  tags = {
    Environment = var.environment
  }
}

resource "aws_elasticache_parameter_group" "redis" {
  name   = "kelvin-${var.environment}-redis7-params"
  family = "redis7"

  parameter {
    name  = "maxmemory-policy"
    value = "noeviction" # Fail fast on queue exhaustion rather than silently dropping tasks
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "kelvin-${var.environment}-redis"
  description                = "KELVIN Assessment Task Queue Broker"
  node_type                  = var.node_type
  num_cache_clusters         = var.num_cache_clusters
  port                       = 6379
  parameter_group_name       = aws_elasticache_parameter_group.redis.name
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = var.security_group_ids
  automatic_failover_enabled = var.num_cache_clusters > 1 ? true : false
  multi_az_enabled           = var.num_cache_clusters > 1 ? true : false
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = {
    Name        = "kelvin-${var.environment}-redis"
    Environment = var.environment
  }
}
