variable "environment" {
  description = "Target deployment environment (dev, staging, prod)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the Virtual Private Cloud"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones for multi-AZ resilience"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDRs for Zone 0 Public Ingress / DMZ subnets"
  type        = list(string)
}

variable "app_subnet_cidrs" {
  description = "CIDRs for Zone 1 Application & API private subnets"
  type        = list(string)
}

variable "worker_subnet_cidrs" {
  description = "CIDRs for Zone 2 Asynchronous Worker private subnets"
  type        = list(string)
}

variable "sandbox_subnet_cidrs" {
  description = "CIDRs for Zone 3 Scanner Sandbox isolated subnets"
  type        = list(string)
}

variable "data_subnet_cidrs" {
  description = "CIDRs for Zone 4 Persistence & Data isolated subnets"
  type        = list(string)
}

variable "enable_nat_gateway" {
  description = "Whether to provision NAT Gateways for private outbound internet"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use single NAT gateway for cost savings in dev/staging"
  type        = bool
  default     = false
}
