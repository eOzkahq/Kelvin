output "alb_id" {
  description = "Application Load Balancer ID"
  value       = aws_lb.alb.id
}

output "alb_dns_name" {
  description = "Public DNS name of the ALB"
  value       = aws_lb.alb.dns_name
}

output "alb_zone_id" {
  description = "Route53 Hosted Zone ID for ALB alias records"
  value       = aws_lb.alb.zone_id
}

output "api_target_group_arn" {
  description = "Target Group ARN for Go API services"
  value       = aws_lb_target_group.api.arn
}
