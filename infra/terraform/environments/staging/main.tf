terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    bucket         = "kelvin-terraform-state-staging"
    key            = "staging/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "kelvin-terraform-locks-staging"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "KELVIN"
      Environment = "staging"
      ManagedBy   = "Terraform"
    }
  }
}

module "networking" {
  source = "../../modules/networking"

  environment          = "staging"
  vpc_cidr             = var.vpc_cidr
  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  app_subnet_cidrs     = var.app_subnet_cidrs
  worker_subnet_cidrs  = var.worker_subnet_cidrs
  sandbox_subnet_cidrs = var.sandbox_subnet_cidrs
  data_subnet_cidrs    = var.data_subnet_cidrs
  enable_nat_gateway   = true
  single_nat_gateway   = true # Single NAT Gateway for Staging Cost Optimization
}

module "security" {
  source = "../../modules/security"

  environment = "staging"
  vpc_id      = module.networking.vpc_id
  vpc_cidr    = var.vpc_cidr
}

module "database" {
  source = "../../modules/database"

  environment           = "staging"
  subnet_ids            = module.networking.data_subnet_ids
  security_group_ids    = [module.security.db_security_group_id]
  instance_class        = "db.t4g.large"
  allocated_storage     = 50
  max_allocated_storage = 250
  multi_az              = true
  deletion_protection   = false
}

module "broker" {
  source = "../../modules/broker"

  environment        = "staging"
  subnet_ids         = module.networking.worker_subnet_ids
  security_group_ids = [module.security.redis_security_group_id]
  node_type          = "cache.t4g.small"
  num_cache_clusters = 2
}

module "storage" {
  source = "../../modules/storage"

  environment     = "staging"
  api_role_arn    = module.security.api_role_arn
  worker_role_arn = module.security.worker_role_arn
}

module "ingress" {
  source = "../../modules/ingress"

  environment           = "staging"
  vpc_id                = module.networking.vpc_id
  public_subnet_ids     = module.networking.public_subnet_ids
  alb_security_group_id = module.security.alb_security_group_id
  certificate_arn       = var.certificate_arn
}

module "compute" {
  source = "../../modules/compute"

  environment              = "staging"
  vpc_id                   = module.networking.vpc_id
  app_subnet_ids           = module.networking.app_subnet_ids
  worker_subnet_ids        = module.networking.worker_subnet_ids
  app_security_group_id    = module.security.app_security_group_id
  worker_security_group_id = module.security.worker_security_group_id
  api_role_arn             = module.security.api_role_arn
  worker_role_arn          = module.security.worker_role_arn
  api_target_group_arn     = module.ingress.api_target_group_arn
  api_desired_count        = 2
  worker_desired_count     = 2
}
