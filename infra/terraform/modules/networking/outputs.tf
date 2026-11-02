output "vpc_id" {
  description = "The ID of the provisioned VPC"
  value       = aws_vpc.kelvin.id
}

output "public_subnet_ids" {
  description = "IDs of the Zone 0 public ingress subnets"
  value       = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  description = "IDs of the Zone 1 application subnets"
  value       = aws_subnet.app[*].id
}

output "worker_subnet_ids" {
  description = "IDs of the Zone 2 worker subnets"
  value       = aws_subnet.worker[*].id
}

output "sandbox_subnet_ids" {
  description = "IDs of the Zone 3 scanner sandbox subnets"
  value       = aws_subnet.sandbox[*].id
}

output "data_subnet_ids" {
  description = "IDs of the Zone 4 isolated data subnets"
  value       = aws_subnet.data[*].id
}

output "nat_gateway_ips" {
  description = "Elastic IP addresses assigned to NAT gateways (for target allowlists)"
  value       = aws_eip.nat[*].public_ip
}
