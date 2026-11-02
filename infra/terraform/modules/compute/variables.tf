variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "app_subnet_ids" {
  description = "Subnet IDs for Go API service (Zone 1)"
  type        = list(string)
}

variable "worker_subnet_ids" {
  description = "Subnet IDs for Worker service (Zone 2)"
  type        = list(string)
}

variable "app_security_group_id" {
  description = "Security group ID for API service"
  type        = string
}

variable "worker_security_group_id" {
  description = "Security group ID for Worker service"
  type        = string
}

variable "api_role_arn" {
  description = "IAM role ARN for API tasks"
  type        = string
}

variable "worker_role_arn" {
  description = "IAM role ARN for Worker tasks"
  type        = string
}

variable "api_target_group_arn" {
  description = "Target group ARN for ALB routing"
  type        = string
}

variable "api_desired_count" {
  description = "Desired number of API container instances"
  type        = number
  default     = 3
}

variable "worker_desired_count" {
  description = "Desired number of Worker container instances"
  type        = number
  default     = 4
}
