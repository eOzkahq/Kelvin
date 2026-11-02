# Security Groups for Zone 0 to Zone 4 Isolation

# Zone 0: Application Load Balancer Security Group
resource "aws_security_group" "alb" {
  name        = "kelvin-${var.environment}-sg-alb"
  description = "Security group for Zone 0 public Application Load Balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "Public HTTPS ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP to HTTPS redirect ingress"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Forward to Zone 1 Go API pods"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name        = "kelvin-${var.environment}-sg-alb"
    Environment = var.environment
  }
}

# Zone 1: Application & Go API Security Group
resource "aws_security_group" "app" {
  name        = "kelvin-${var.environment}-sg-app"
  description = "Security group for Zone 1 Go API and Application services"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Inbound traffic from ALB only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Egress to PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Egress to Redis Broker"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Egress for external IdP and AWS APIs (HTTPS)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "kelvin-${var.environment}-sg-app"
    Environment = var.environment
  }
}

# Zone 2: Asynchronous Worker Fleet Security Group
resource "aws_security_group" "worker" {
  name        = "kelvin-${var.environment}-sg-worker"
  description = "Security group for Zone 2 Assessment Worker orchestrators"
  vpc_id      = var.vpc_id

  egress {
    description = "Egress to Redis task broker"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Egress to PostgreSQL for result persistence"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS to S3 and internal control endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "kelvin-${var.environment}-sg-worker"
    Environment = var.environment
  }
}

# Zone 3: Scanner Execution Sandbox Security Group
resource "aws_security_group" "sandbox" {
  name        = "kelvin-${var.environment}-sg-sandbox"
  description = "Security group for Zone 3 rootless scanner pods (Zero access to DB/Internal VPC)"
  vpc_id      = var.vpc_id

  # Zero internal ingress
  # Egress restricted strictly to target scanning (HTTP/HTTPS) and S3 presigned upload
  egress {
    description = "Outbound HTTP target assessment"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound HTTPS target assessment and S3 presigned upload"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "kelvin-${var.environment}-sg-sandbox"
    Environment = var.environment
  }
}

# Zone 2 Broker: Redis Security Group
resource "aws_security_group" "redis" {
  name        = "kelvin-${var.environment}-sg-redis"
  description = "Security group for Redis message queue broker"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow Redis access from API tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  ingress {
    description     = "Allow Redis access from Worker tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.worker.id]
  }

  tags = {
    Name        = "kelvin-${var.environment}-sg-redis"
    Environment = var.environment
  }
}

# Zone 4 Data: PostgreSQL Security Group
resource "aws_security_group" "db" {
  name        = "kelvin-${var.environment}-sg-db"
  description = "Security group for Zone 4 PostgreSQL persistence layer"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Postgres access from API tier (PgBouncer)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  ingress {
    description     = "Postgres access from Worker tier for finding persistence"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.worker.id]
  }

  # Zero outbound internet
  tags = {
    Name        = "kelvin-${var.environment}-sg-db"
    Environment = var.environment
  }
}

# IAM Role: Least-Privilege API Service Role
resource "aws_iam_role" "api_role" {
  name = "kelvin-${var.environment}-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

# IAM Role: Least-Privilege Worker Service Role
resource "aws_iam_role" "worker_role" {
  name = "kelvin-${var.environment}-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

# IAM Role: Scanner Task Execution Role (Zero IAM privileges, CloudWatch logs only)
resource "aws_iam_role" "scanner_role" {
  name = "kelvin-${var.environment}-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}
