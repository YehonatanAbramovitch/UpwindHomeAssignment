# Which Terraform and which providers this code needs.
# Versions are pinned so every run, including the live demo, behaves the same.

terraform {
  required_version = "~> 1.17.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.23.0 is the first version that can use `aws login` credentials.
      version = ">= 6.23.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region

  # Added to every resource this code creates, so the project's resources can be
  # found (and checked as removed) by one tag search, and its cost seen in Billing.
  default_tags {
    tags = {
      Project = var.project
    }
  }
}
