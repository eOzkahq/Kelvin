output "certificate_arn" {
  description = "Validated ACM certificate ARN for TLS termination"
  value       = aws_acm_certificate_validation.cert.certificate_arn
}

output "app_fqdn" {
  description = "Fully Qualified Domain Name for Frontend Application"
  value       = aws_route53_record.app.fqdn
}

output "api_fqdn" {
  description = "Fully Qualified Domain Name for API Control Plane"
  value       = aws_route53_record.api.fqdn
}
