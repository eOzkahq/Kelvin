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
    bucket         = "kelvin-terraform-state-dev"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "kelvin-terraform-locks-dev"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "KELVIN"
      Environment = "dev"
      ManagedBy   = "Terraform"
    }
  }
}

module "networking" {
  source = "../../modules/networking"

  environment          = "dev"
  vpc_cidr             = var.vpc_cidr
  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  app_subnet_cidrs     = var.app_subnet_cidrs
  worker_subnet_cidrs  = var.worker_subnet_cidrs
  sandbox_subnet_cidrs = var.sandbox_subnet_cidrs
  data_subnet_cidrs    = var.data_subnet_cidrs
  enable_nat_gateway   = true
  single_nat_gateway   = true
}

module "security" {
  source = "../../modules/security"

  environment = "dev"
  vpc_id      = module.networking.vpc_id
  vpc_cidr    = var.vpc_cidr
}

module "database" {
  source = "../../modules/database"

  environment           = "dev"
  subnet_ids            = module.networking.data_subnet_ids
  security_group_ids    = [module.security.db_security_group_id]
  instance_class        = "db.t4g.micro"
  allocated_storage     = 20
  max_allocated_storage = 50
  multi_az              = false
  deletion_protection   = false
}

module "broker" {
  source = "../../modules/broker"

  environment        = "dev"
  subnet_ids         = module.networking.worker_subnet_ids
  security_group_ids = [module.security.redis_security_group_id]
  node_type          = "cache.t4g.micro"
  num_cache_clusters = 1
}

module "storage" {
  source = "../../modules/storage"

  environment     = "dev"
  api_role_arn    = module.security.api_role_arn
  worker_role_arn = module.security.worker_role_arn
}

module "ingress" {
  source = "../../modules/ingress"

  environment           = "dev"
  vpc_id                = module.networking.vpc_id
  public_subnet_ids     = module.networking.public_subnet_ids
  alb_security_group_id = module.security.alb_security_group_id
  certificate_arn       = var.certificate_arn
}

module "compute" {
  source = "../../modules/compute"

  environment              = "dev"
  vpc_id                   = module.networking.vpc_id
  app_subnet_ids           = module.networking.app_subnet_ids
  worker_subnet_ids        = module.networking.worker_subnet_ids
  app_security_group_id    = module.security.app_security_group_id
  worker_security_group_id = module.security.worker_security_group_id
  api_role_arn             = module.security.api_role_arn
  worker_role_arn          = module.security.worker_role_arn
  api_target_group_arn     = module.ingress.api_target_group_arn
  api_desired_count        = 1
  worker_desired_count     = 1
}
