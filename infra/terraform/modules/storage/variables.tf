variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "api_role_arn" {
  description = "IAM role ARN of API service allowed to generate presigned URLs and manage reports"
  type        = string
}

variable "worker_role_arn" {
  description = "IAM role ARN of Worker service allowed to read/write evidence"
  type        = string
}
