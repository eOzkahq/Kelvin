# Production DNS (Route53) and TLS Certificates (ACM)

# Route53 Hosted Zone lookup
data "aws_route53_zone" "primary" {
  name         = var.domain_name
  private_zone = false
}

# ACM Public TLS Certificate with Subject Alternative Names
resource "aws_acm_certificate" "kelvin_cert" {
  domain_name       = var.environment == "prod" ? "app.${var.domain_name}" : "${var.environment}-app.${var.domain_name}"
  validation_method = "DNS"

  subject_alternative_names = [
    var.environment == "prod" ? "api.${var.domain_name}" : "${var.environment}-api.${var.domain_name}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Automated DNS Validation Records
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.kelvin_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.primary.zone_id
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.kelvin_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Route53 Alias Records for Frontend App and API
resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = var.environment == "prod" ? "app.${var.domain_name}" : "${var.environment}-app.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = var.environment == "prod" ? "api.${var.domain_name}" : "${var.environment}-api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
