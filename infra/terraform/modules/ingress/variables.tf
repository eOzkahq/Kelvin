variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnet_ids" {
  description = "Subnet IDs for public load balancer (Zone 0)"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group for the ALB"
  type        = string
}

variable "certificate_arn" {
  description = "ACM Certificate ARN for TLS termination"
  type        = string
  default     = ""
}
