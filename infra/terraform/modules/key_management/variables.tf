variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "api_role_arn" {
  description = "IAM Role ARN for the API service"
  type        = string
}

variable "worker_role_arn" {
  description = "IAM Role ARN for the Worker service"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Key ARN for secrets encryption"
  type        = string
  default     = ""
}
