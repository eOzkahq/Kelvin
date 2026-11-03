variable "aws_region" {
  description = "Target AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR for Development"
  type        = string
  default     = "10.100.0.0/16"
}

variable "availability_zones" {
  description = "List of Availability Zones in region"
  type        = list(string)
  default     = ["us-east-1a"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.1.0/24"]
}

variable "app_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.10.0/24"]
}

variable "worker_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.20.0/24"]
}

variable "sandbox_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.30.0/24"]
}

variable "data_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.40.0/24"]
}

variable "certificate_arn" {
  description = "ACM Certificate ARN for dev domain"
  type        = string
  default     = ""
}
