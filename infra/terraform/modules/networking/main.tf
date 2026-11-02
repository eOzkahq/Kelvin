# KELVIN VPC & Subnet Architecture (Zone 0 to Zone 4)

resource "aws_vpc" "kelvin" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "kelvin-${var.environment}-vpc"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Internet Gateway for Public Edge DMZ
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.kelvin.id

  tags = {
    Name        = "kelvin-${var.environment}-igw"
    Environment = var.environment
  }
}

# Zone 0: Public Ingress Subnets (ALB & Edge)
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.kelvin.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "kelvin-${var.environment}-public-${var.availability_zones[count.index]}"
    Zone        = "Zone-0-EdgeDMZ"
    Environment = var.environment
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnet_cidrs)) : 0
  domain = "vpc"

  tags = {
    Name        = "kelvin-${var.environment}-nat-eip-${count.index + 1}"
    Environment = var.environment
  }
}

# NAT Gateways for Private Egress
resource "aws_nat_gateway" "nat" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnet_cidrs)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name        = "kelvin-${var.environment}-nat-${count.index + 1}"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.gw]
}

# Route Table for Public Subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.kelvin.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name        = "kelvin-${var.environment}-public-rt"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Zone 1: Application Private Subnets (Go API & PgBouncer)
resource "aws_subnet" "app" {
  count             = length(var.app_subnet_cidrs)
  vpc_id            = aws_vpc.kelvin.id
  cidr_block        = var.app_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "kelvin-${var.environment}-app-${var.availability_zones[count.index]}"
    Zone        = "Zone-1-AppTier"
    Environment = var.environment
  }
}

# Zone 2: Worker Private Subnets (Runners & Redis)
resource "aws_subnet" "worker" {
  count             = length(var.worker_subnet_cidrs)
  vpc_id            = aws_vpc.kelvin.id
  cidr_block        = var.worker_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "kelvin-${var.environment}-worker-${var.availability_zones[count.index]}"
    Zone        = "Zone-2-WorkerTier"
    Environment = var.environment
  }
}

# Route Tables for Private App and Worker Subnets (Via NAT)
resource "aws_route_table" "private" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.kelvin.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.nat[0].id : aws_nat_gateway.nat[count.index].id
    }
  }

  tags = {
    Name        = "kelvin-${var.environment}-private-rt-${var.availability_zones[count.index]}"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "app" {
  count          = length(aws_subnet.app)
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "worker" {
  count          = length(aws_subnet.worker)
  subnet_id      = aws_subnet.worker[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Zone 3: Scanner Execution Sandbox Subnets (Isolated Egress)
resource "aws_subnet" "sandbox" {
  count             = length(var.sandbox_subnet_cidrs)
  vpc_id            = aws_vpc.kelvin.id
  cidr_block        = var.sandbox_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "kelvin-${var.environment}-sandbox-${var.availability_zones[count.index]}"
    Zone        = "Zone-3-ScannerSandbox"
    Environment = var.environment
  }
}

resource "aws_route_table" "sandbox" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.kelvin.id

  # Only outbound default route through dedicated NAT for scan targets
  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.nat[0].id : aws_nat_gateway.nat[count.index].id
    }
  }

  tags = {
    Name        = "kelvin-${var.environment}-sandbox-rt-${var.availability_zones[count.index]}"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "sandbox" {
  count          = length(aws_subnet.sandbox)
  subnet_id      = aws_subnet.sandbox[count.index].id
  route_table_id = aws_route_table.sandbox[count.index].id
}

# Zone 4: Data Subnets (Completely Isolated - Zero Direct Internet Egress)
resource "aws_subnet" "data" {
  count             = length(var.data_subnet_cidrs)
  vpc_id            = aws_vpc.kelvin.id
  cidr_block        = var.data_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "kelvin-${var.environment}-data-${var.availability_zones[count.index]}"
    Zone        = "Zone-4-DataTier"
    Environment = var.environment
  }
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.kelvin.id

  # No default 0.0.0.0/0 route. Pure internal routing only.
  tags = {
    Name        = "kelvin-${var.environment}-data-rt-isolated"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "data" {
  count          = length(aws_subnet.data)
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}
