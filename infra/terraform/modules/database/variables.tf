variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "subnet_ids" {
  description = "List of Zone 4 isolated data subnet IDs"
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security groups allowed to access the database"
  type        = list(string)
}

variable "instance_class" {
  description = "Database instance compute sizing"
  type        = string
  default     = "db.t4g.medium"
}

variable "allocated_storage" {
  description = "Initial storage in GB"
  type        = number
  default     = 50
}

variable "max_allocated_storage" {
  description = "Maximum storage auto-scaling in GB"
  type        = number
  default     = 500
}

variable "multi_az" {
  description = "Enable Multi-AZ high availability"
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Prevent accidental database deletion"
  type        = bool
  default     = true
}

variable "database_name" {
  description = "Name of default database"
  type        = string
  default     = "kelvin"
}

variable "admin_username" {
  description = "Database administrator username"
  type        = string
  default     = "kelvin_admin"
}
