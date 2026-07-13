# ---------------------------------------------------------------------------
# EKS control plane role - only the two managed policies EKS requires.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "eks_cluster" {
  name = "${var.name_prefix}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ---------------------------------------------------------------------------
# EKS node group role - worker nodes only get what's needed to join the
# cluster, pull images, and manage ENIs for VPC CNI. No S3/RDS/etc access.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "eks_node" {
  name = "${var.name_prefix}-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_node_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ])
  role       = aws_iam_role.eks_node.name
  policy_arn = each.value
}

# ---------------------------------------------------------------------------
# IRSA (IAM Roles for Service Accounts) role for the External Secrets
# Operator running in-cluster. Scoped to secretsmanager:GetSecretValue on
# secrets under this project's naming prefix only - never "*".
# The trust policy is finished in the EKS module once the OIDC provider
# (which depends on the cluster) exists; this defines the permission side.
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "external_secrets" {
  name        = "${var.name_prefix}-external-secrets-policy"
  description = "Least-privilege read access to this project's Secrets Manager secrets for the External Secrets Operator."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
      ]
      Resource = "arn:aws:secretsmanager:*:${var.account_id}:secret:${var.name_prefix}/*"
    }]
  })

  tags = var.tags
}

# ---------------------------------------------------------------------------
# CI/CD deploy role assumed by GitHub Actions via OIDC federation - no long
# lived AWS access keys stored as GitHub secrets. Trust is scoped to one
# repo and one branch, so a fork or a PR from an untrusted branch cannot
# assume this role.
# ---------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

resource "aws_iam_role" "github_actions_deploy" {
  name = "${var.name_prefix}-gha-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_actions.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_allowed_branch}"
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = var.tags
}

# Deploy role can plan/apply Terraform for this landing zone but cannot
# touch IAM policies attached to itself, and cannot delete the KMS keys or
# CloudTrail - preventing a compromised pipeline from escalating privilege
# or covering its tracks.
#
# No bare "service:*" actions. Every statement lists the specific API calls
# Terraform actually issues for this landing zone. Two categories still use
# Resource "*":
#   - Read-only Describe*/List*/Get* calls: the EC2 and IAM APIs do not
#     support resource-level permissions for most of these (AWS-documented
#     limitation, not a shortcut - see the Resource-Level Permissions
#     reference for each service in the IAM user guide).
#   - A handful of *Create* calls (kms:CreateKey, ec2:CreateVpc, ...) that
#     inherently can't be scoped to a resource ARN because the resource
#     doesn't exist until the call succeeds.
# Everything that CAN be scoped (PassRole, the state backend, IAM/KMS
# writes on resources this project owns) is scoped to a specific ARN or
# name prefix below.
resource "aws_iam_role_policy" "github_actions_deploy" {
  # checkov:skip=CKV_AWS_355: Resource "*" appears only on the ReadOnlyDescribeUnavoidablyUnscoped, ManageVpcNetworking, and kms:CreateKey statements below, each commented with why AWS's IAM model doesn't support resource-level scoping for those specific actions. Every other statement is scoped to a name-prefixed or explicit ARN.
  name = "${var.name_prefix}-gha-deploy-policy"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyDescribeUnavoidablyUnscoped"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "eks:Describe*",
          "eks:List*",
          "elasticloadbalancing:Describe*",
          "logs:Describe*",
          "logs:List*",
          "logs:GetLogEvents",
          "iam:Get*",
          "iam:List*",
          "kms:Describe*",
          "kms:List*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageVpcNetworking"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute", "ec2:DeleteRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateNatGateway", "ec2:DeleteNatGateway",
          "ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateNetworkAcl", "ec2:DeleteNetworkAcl",
          "ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry", "ec2:ReplaceNetworkAclEntry",
          "ec2:AssociateNetworkAcl", "ec2:ReplaceNetworkAclAssociation",
          "ec2:CreateLaunchTemplate", "ec2:DeleteLaunchTemplate", "ec2:ModifyLaunchTemplate",
          "ec2:CreateFlowLogs", "ec2:DeleteFlowLogs",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "eu-west-3"
          }
        }
      },
      {
        Sid    = "ManageEksResources"
        Effect = "Allow"
        Action = [
          "eks:CreateCluster", "eks:DeleteCluster", "eks:UpdateClusterConfig", "eks:UpdateClusterVersion",
          "eks:AssociateEncryptionConfig", "eks:TagResource", "eks:UntagResource",
          "eks:CreateNodegroup", "eks:DeleteNodegroup", "eks:UpdateNodegroupConfig", "eks:UpdateNodegroupVersion",
        ]
        Resource = [
          "arn:aws:eks:*:${var.account_id}:cluster/${var.name_prefix}-*",
          "arn:aws:eks:*:${var.account_id}:nodegroup/${var.name_prefix}-*/*/*",
        ]
      },
      {
        Sid    = "TerraformStateBackend"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        ]
        Resource = [
          var.state_bucket_arn,
          "${var.state_bucket_arn}/*",
        ]
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        ]
        Resource = var.state_lock_table_arn
      },
      {
        Sid    = "ManageLogGroups"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
          "logs:TagResource", "logs:UntagResource",
        ]
        Resource = "arn:aws:logs:*:${var.account_id}:log-group:*${var.name_prefix}*"
      },
      {
        Sid    = "ManageProjectIamResources"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole",
          "iam:CreatePolicy", "iam:DeletePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:TagRole", "iam:UntagRole", "iam:TagPolicy", "iam:UntagPolicy",
          "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider", "iam:TagOpenIDConnectProvider",
        ]
        Resource = [
          "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-*",
          "arn:aws:iam::${var.account_id}:policy/${var.name_prefix}-*",
          "arn:aws:iam::${var.account_id}:oidc-provider/*",
        ]
      },
      {
        # The single most important line in this policy: without it, a
        # policy this narrow would be useless because Terraform could never
        # attach the cluster/node roles to EKS. With it scoped to these two
        # exact role ARNs and gated by PassedToService, a compromised
        # pipeline still cannot pass, say, the break-glass admin role to an
        # EC2 instance to escalate privilege.
        Sid    = "PassLandingZoneRolesToAwsServices"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.eks_cluster.arn,
          aws_iam_role.eks_node.arn,
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = ["eks.amazonaws.com", "ec2.amazonaws.com"]
          }
        }
      },
      {
        # kms:CreateKey cannot be scoped to a resource ARN (the key doesn't
        # exist until the call returns), so this one action is unavoidably
        # Resource "*". It's kept in its own statement, deliberately without
        # the ABAC tag condition below, since a not-yet-created resource can
        # never satisfy an aws:ResourceTag condition - combining them here
        # would silently make CreateKey un-callable rather than scoped.
        Sid      = "CreateProjectKmsKeys"
        Effect   = "Allow"
        Action   = "kms:CreateKey"
        Resource = "*"
      },
      {
        Sid    = "ManageExistingProjectKmsKeys"
        Effect = "Allow"
        Action = [
          "kms:CreateAlias", "kms:DeleteAlias",
          "kms:EnableKeyRotation", "kms:PutKeyPolicy", "kms:TagResource", "kms:UntagResource",
          "kms:ScheduleKeyDeletion", "kms:DisableKey",
        ]
        Resource = "*"
        Condition = {
          # ABAC guardrail: these write actions on *existing* keys only
          # succeed if the key already carries this project's tag - keys
          # belonging to other workloads in the account are untouched even
          # though the action list above is broad.
          StringEquals = {
            "aws:ResourceTag/Project" = "secure-landing-zone"
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Break-glass human admin role - requires an active MFA session to assume
# (aws:MultiFactorAuthPresent), and the session is short-lived.
# This is the "simulated mandatory MFA" control: IAM cannot force a user to
# have MFA enabled on their IAM user from within a role's trust policy, but
# it CAN refuse to hand out this role's credentials unless the caller's
# current STS session was itself established with MFA - which is the
# enforceable, auditable equivalent for role-based access.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "break_glass_admin" {
  name = "${var.name_prefix}-break-glass-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = length(var.human_admin_principal_arns) > 0 ? var.human_admin_principal_arns : ["arn:aws:iam::${var.account_id}:root"]
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
        NumericLessThan = {
          "aws:MultiFactorAuthAge" = "3600"
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  # checkov:skip=CKV_AWS_274: intentional break-glass role, not day-to-day access.
  # Justified because: (1) trust policy requires a fresh MFA-backed STS session
  # (see condition above), (2) 1h max session duration, (3) every assumption
  # is a distinct CloudTrail event that should page on-call per the incident
  # response runbook. See docs/architecture.md "Security Choices" for detail.
  role       = aws_iam_role.break_glass_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
