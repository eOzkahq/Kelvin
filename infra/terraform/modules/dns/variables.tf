variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "domain_name" {
  description = "Apex domain name (e.g., kelvinsecurity.io)"
  type        = string
  default     = "kelvinsecurity.io"
}

variable "alb_dns_name" {
  description = "ALB DNS Name for Route53 Alias Target"
  type        = string
}

variable "alb_zone_id" {
  description = "ALB Canonical Hosted Zone ID"
  type        = string
}
