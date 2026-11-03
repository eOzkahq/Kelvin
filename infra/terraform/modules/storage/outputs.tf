output "evidence_bucket_name" {
  description = "Name of the evidence S3 bucket"
  value       = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence S3 bucket"
  value       = aws_s3_bucket.evidence.arn
}

output "reports_bucket_name" {
  description = "Name of the reports S3 bucket"
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the reports S3 bucket"
  value       = aws_s3_bucket.reports.arn
}

output "kms_key_arn" {
  description = "KMS key ARN used for storage encryption"
  value       = aws_kms_key.storage_key.arn
}
