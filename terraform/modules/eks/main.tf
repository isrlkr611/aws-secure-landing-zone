data "aws_partition" "current" {}

# ---------------------------------------------------------------------------
# Control plane logging - all five log types shipped to CloudWatch, encrypted
# with our own KMS key. Without this, API server audit events (who did what)
# are not retained anywhere, which defeats incident response.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "eks_control_plane" {
  name              = "/aws/eks/${var.name_prefix}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# Security group for the control plane <-> node communication. No ingress
# from 0.0.0.0/0 anywhere - only from the VPC CIDR and node SG itself.
# ---------------------------------------------------------------------------
resource "aws_security_group" "cluster" {
  name_prefix = "${var.name_prefix}-eks-cluster-"
  vpc_id      = var.vpc_id
  description = "EKS control plane ENIs"

  tags = merge(var.tags, { Name = "${var.name_prefix}-eks-cluster-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

# Control plane ENIs live in private subnets with no route to an Internet
# Gateway (see vpc module); 0.0.0.0/0 here is reachable only via the NAT
# Gateway, and is required because the control plane calls regional AWS
# APIs (ECR, STS, CloudWatch Logs) whose IP ranges are broad and change
# over time. Scoping this to AWS service prefix lists instead of full
# internet would be a further hardening step for a production rollout
# beyond this portfolio's scope.
# tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group_rule" "cluster_egress_all" {
  # checkov:skip=CKV_AWS_382: see justification above - NAT-gated egress from a private-subnet-only ENI, not a public exposure.
  security_group_id = aws_security_group.cluster.id
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Control plane needs outbound to AWS APIs and node kubelets"
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.name_prefix}-eks-nodes-"
  vpc_id      = var.vpc_id
  description = "EKS worker nodes"

  tags = merge(var.tags, {
    Name                                           = "${var.name_prefix}-eks-nodes-sg"
    "kubernetes.io/cluster/${var.name_prefix}-eks" = "owned"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "nodes_ingress_self" {
  security_group_id        = aws_security_group.nodes.id
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.nodes.id
  description              = "Node to node communication"
}

resource "aws_security_group_rule" "nodes_ingress_cluster" {
  security_group_id        = aws_security_group.nodes.id
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  description              = "Control plane to kubelet"
}

resource "aws_security_group_rule" "cluster_ingress_nodes_https" {
  security_group_id        = aws_security_group.cluster.id
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nodes.id
  description              = "Nodes to control plane API"
}

# Same reasoning as the control plane's egress rule above: private-
# subnet-only, NAT-gated, and needed for image pulls from arbitrary
# registries plus AWS API calls whose source IP ranges aren't practical to
# enumerate here.
# tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group_rule" "nodes_egress_all" {
  # checkov:skip=CKV_AWS_382: see justification above - NAT-gated egress from a private-subnet-only ENI, not a public exposure.
  security_group_id = aws_security_group.nodes.id
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Nodes need outbound via NAT (image pulls, AWS APIs)"
}

# Explicitly NOT creating any ingress rule for port 22 (SSH) anywhere in this
# module - worker node access is via SSM Session Manager (IAM + audit logged),
# never via a directly-reachable SSH port.

# ---------------------------------------------------------------------------
# EKS cluster
# ---------------------------------------------------------------------------
resource "aws_eks_cluster" "this" {
  name     = "${var.name_prefix}-eks"
  role_arn = var.cluster_role_arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access ? var.cluster_endpoint_public_access_cidrs : null
  }

  # Envelope-encrypt Kubernetes Secrets objects in etcd with our own KMS key,
  # on top of the encryption at rest EKS already does for the etcd volumes.
  encryption_config {
    provider {
      key_arn = var.eks_secrets_kms_key_arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  tags = var.tags

  depends_on = [aws_cloudwatch_log_group.eks_control_plane]
}

# ---------------------------------------------------------------------------
# OIDC provider for IRSA (IAM Roles for Service Accounts) - lets pods assume
# narrowly-scoped IAM roles (e.g. External Secrets Operator) instead of
# inheriting the node's IAM role, which would be far too broad.
# ---------------------------------------------------------------------------
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  tags            = var.tags
}

# ---------------------------------------------------------------------------
# Managed node group - private subnets only, encrypted EBS via customer KMS
# key, IMDSv2 enforced (hop limit 1, no unauthenticated IMDS), no public IP.
# ---------------------------------------------------------------------------
resource "aws_launch_template" "nodes" {
  name_prefix = "${var.name_prefix}-eks-node-"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.nodes.id]
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name_prefix}-eks-node" })
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name_prefix}-default"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = var.node_instance_types

  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  tags = var.tags

  depends_on = [aws_eks_cluster.this]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}
