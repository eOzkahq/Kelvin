# Container Compute Infrastructure (AWS ECS Fargate)

resource "aws_ecs_cluster" "main" {
  name = "kelvin-${var.environment}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "kelvin-${var.environment}-ecs-cluster"
    Environment = var.environment
  }
}

# CloudWatch Log Groups for Logging & Observability
resource "aws_cloudwatch_log_group" "api" {
  name              = "/kelvin/${var.environment}/api"
  retention_in_days = 30

  tags = {
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/kelvin/${var.environment}/worker"
  retention_in_days = 30

  tags = {
    Environment = var.environment
  }
}

# API Task Definition & Service
resource "aws_ecs_task_definition" "api" {
  family                   = "kelvin-${var.environment}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = var.api_role_arn
  task_role_arn            = var.api_role_arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "kelvin/api:${var.environment}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "api"
        }
      }
      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "PORT", value = "8080" }
      ]
    }
  ])

  tags = {
    Environment = var.environment
  }
}

resource "aws_ecs_service" "api" {
  name            = "kelvin-${var.environment}-api-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.app_subnet_ids
    security_groups = [var.app_security_group_id]
  }

  load_balancer {
    target_group_arn = var.api_target_group_arn
    container_name   = "api"
    container_port   = 8080
  }

  deployment_controller {
    type = "ECS"
  }

  tags = {
    Environment = var.environment
  }
}

# Worker Task Definition & Service
resource "aws_ecs_task_definition" "worker" {
  family                   = "kelvin-${var.environment}-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "2048"
  memory                   = "4096"
  execution_role_arn       = var.worker_role_arn
  task_role_arn            = var.worker_role_arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = "kelvin/worker:${var.environment}"
      essential = true
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "worker"
        }
      }
      environment = [
        { name = "ENVIRONMENT", value = var.environment }
      ]
    }
  ])

  tags = {
    Environment = var.environment
  }
}

resource "aws_ecs_service" "worker" {
  name            = "kelvin-${var.environment}-worker-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.worker_subnet_ids
    security_groups = [var.worker_security_group_id]
  }

  tags = {
    Environment = var.environment
  }
}

# Horizontal Pod / Task Autoscaling for API
resource "aws_appautoscaling_target" "api" {
  max_capacity       = 24
  min_capacity       = var.api_desired_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "kelvin-${var.environment}-api-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 65.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
