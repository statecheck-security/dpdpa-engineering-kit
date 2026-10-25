terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  alias  = "ap_south_1"
  region = "ap-south-1" # Mumbai
}

data "aws_caller_identity" "current" {
  provider = aws.ap_south_1
}

variable "residency_admin_role_arn" {
  description = "The only IAM role allowed to configure replication on the India bucket."
  type        = string
}
