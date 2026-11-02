variable "aws_region" {
  description = "Target AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR for Staging"
  type        = string
  default     = "10.200.0.0/16"
}

variable "availability_zones" {
  description = "List of Availability Zones in region"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.200.1.0/24", "10.200.2.0/24"]
}

variable "app_subnet_cidrs" {
  type    = list(string)
  default = ["10.200.10.0/24", "10.200.11.0/24"]
}

variable "worker_subnet_cidrs" {
  type    = list(string)
  default = ["10.200.20.0/24", "10.200.21.0/24"]
}

variable "sandbox_subnet_cidrs" {
  type    = list(string)
  default = ["10.200.30.0/24", "10.200.31.0/24"]
}

variable "data_subnet_cidrs" {
  type    = list(string)
  default = ["10.200.40.0/24", "10.200.41.0/24"]
}

variable "certificate_arn" {
  description = "ACM Certificate ARN for staging domain"
  type        = string
  default     = "arn:aws:acm:us-east-1:123456789012:certificate/example-staging-cert"
}
