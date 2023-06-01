locals {
  cluster_name = "my-eks-fargate-cluster"
}

resource "aws_vpc" "this" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = local.cluster_name
  }
}

resource "aws_subnet" "private" {
  count = 2

  cidr_block = "10.0.${count.index + 1}.0/24"
  vpc_id     = aws_vpc.this.id

  tags = {
    Name = "${local.cluster_name}-private-${count.index + 1}"
  }
}

resource "aws_subnet" "public" {
  count = 2

  cidr_block = "10.0.${count.index + 101}.0/24"
  vpc_id     = aws_vpc.this.id

  tags = {
    Name = "${local.cluster_name}-public-${count.index + 1}"
  }
}

resource "aws_security_group" "worker_group_mgmt_one" {
  name_prefix = "worker_group_mgmt_one"
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group" "worker_group_mgmt_two" {
  name_prefix = "worker_group_mgmt_two"
  vpc_id      = aws_vpc.this.id
}

module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = local.cluster_name

  subnets = concat(aws_subnet.private.*.id, aws_subnet.public.*.id)

  tags = {
    Terraform = "true"
    Module    = "terraform-aws-modules/eks/aws"
  }

  vpc_id = aws_vpc.this.id

  # EKS Fargate config
  fargate_profiles = {
    default = {
      namespace = "default"
    }
    kube_system = {
      namespace = "kube-system"
    }
  }
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane."
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster."
  value       = module.eks.cluster_security_group_id
}

output "cluster_arn" {
  description = "ARN of the EKS cluster."
  value       = module.eks.cluster_arn
}
