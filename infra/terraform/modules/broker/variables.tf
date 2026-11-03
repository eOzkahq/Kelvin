variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for Redis deployment (Zone 2)"
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security group IDs for Redis"
  type        = list(string)
}

variable "node_type" {
  description = "ElastiCache node instance type"
  type        = string
  default     = "cache.t4g.small"
}

variable "num_cache_clusters" {
  description = "Number of cache clusters for replication group"
  type        = number
  default     = 2
}
