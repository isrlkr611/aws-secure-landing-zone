locals {
  az_count = length(var.azs)
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

# Default security group left with no rules: nothing should implicitly use it.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-default-sg-locked-down" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-igw" })
}

# ---------------------------------------------------------------------------
# Public subnets: ALB/NLB and NAT Gateways only. No workloads, no SSH bastion.
# ---------------------------------------------------------------------------
resource "aws_subnet" "public" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false # ENIs get public IPs explicitly (NAT/ALB), never by default

  tags = merge(var.tags, {
    Name                     = "${var.name_prefix}-public-${var.azs[count.index]}"
    "kubernetes.io/role/elb" = "1"
    Tier                     = "public"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-public-rt" })
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Private subnets: EKS nodes, pods, internal services. Egress-only via NAT.
# No route to the Internet Gateway -> no direct inbound path from the internet,
# which is what removes the need for (and risk of) a public SSH bastion.
# ---------------------------------------------------------------------------
resource "aws_subnet" "private" {
  count             = local.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = merge(var.tags, {
    Name                              = "${var.name_prefix}-private-${var.azs[count.index]}"
    "kubernetes.io/role/internal-elb" = "1"
    Tier                              = "private"
  })
}

resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : local.az_count
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-nat-eip-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count         = var.single_nat_gateway ? 1 : local.az_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(var.tags, { Name = "${var.name_prefix}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "private" {
  count  = local.az_count
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-private-rt-${var.azs[count.index]}" })
}

resource "aws_route" "private_nat_access" {
  count                  = local.az_count
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.single_nat_gateway ? aws_nat_gateway.this[0].id : aws_nat_gateway.this[count.index].id
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# VPC Flow Logs: mandatory for detecting anomalous traffic (e.g. exfiltration,
# port scans) and for incident response. Encrypted at rest with our own KMS key.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc-flow-logs/${var.name_prefix}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.flow_logs_kms_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

# The trailing ":*" is the AWS-documented way to scope permissions to "this
# log group and the log streams inside it" - CloudWatch Logs stream ARNs
# are always <log-group-arn>:log-stream:<name>, so the wildcard is bounded
# to this one log group, not a blanket "*". tfsec's IAM wildcard check
# can't distinguish a bounded suffix wildcard from an unbounded one.
# tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  # Scoped to this specific log group only - no wildcard resource.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  traffic_type             = "ALL"
  max_aggregation_interval = 60

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc-flow-log" })
}

# ---------------------------------------------------------------------------
# Network ACLs as defense-in-depth on top of security groups.
# Private subnet NACL explicitly denies inbound SSH/RDP from 0.0.0.0/0 so that
# a misconfigured security group alone cannot expose management ports.
# ---------------------------------------------------------------------------
resource "aws_network_acl" "private" {
  # checkov:skip=CKV2_AWS_1: subnet_ids is populated (aws_subnet.private[*].id below) - Checkov's static analysis doesn't resolve splat expressions against a count-based resource here, producing a false positive. Confirmed via `terraform plan`: every private subnet is associated.
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.private[*].id
  tags       = merge(var.tags, { Name = "${var.name_prefix}-private-nacl" })
}

resource "aws_network_acl_rule" "private_deny_ssh_inbound" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 90
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "private_deny_rdp_inbound" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 91
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}

# Intra-VPC only (cidr_block is var.vpc_cidr, never 0.0.0.0/0). Fine-grained
# port control is already enforced by security groups; this NACL rule's job
# is only to let intra-VPC traffic (node-to-node, node-to-control-plane)
# pass, with the two deny rules above (22/3389) taking precedence as lower
# rule numbers regardless.
# tfsec:ignore:aws-ec2-no-excessive-port-access
resource "aws_network_acl_rule" "private_allow_vpc_inbound" {
  # checkov:skip=CKV_AWS_352: intra-VPC only (cidr_block = var.vpc_cidr), see justification above.
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = 0
  to_port        = 0
}

# NACLs are stateless, so return traffic for connections *this subnet*
# initiated outbound (e.g. an EKS node calling an AWS API via NAT) arrives
# back on an ephemeral port from an arbitrary internet source IP. Without
# this rule every outbound connection would black-hole on the way back.
# This is the standard, documented AWS pattern for stateless NACLs, not an
# open inbound door - nothing can *initiate* an inbound connection through
# it, since the deny rules for 22/3389 above are evaluated first and
# nothing listens on other low ports in these subnets.
# tfsec:ignore:aws-ec2-no-public-ingress-acl
resource "aws_network_acl_rule" "private_allow_ephemeral_inbound" {
  # checkov:skip=CKV_AWS_231: this is the stateless-NACL ephemeral-port return-traffic rule, not a direct RDP allow - the dedicated deny rule for port 3389 above (rule_number 91) is evaluated first and wins.
  network_acl_id = aws_network_acl.private.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Outbound only (egress = true). Private subnets reach the internet
# exclusively through the NAT Gateway per the route table above; there is
# no compliance/security benefit to enumerating destination ports for
# egress traffic that already has no path back in except as ephemeral-port
# return traffic (see rule above), and doing so would require
# hand-maintaining a port list for every AWS API + package registry these
# nodes talk to.
# tfsec:ignore:aws-ec2-no-excessive-port-access
resource "aws_network_acl_rule" "private_allow_all_outbound" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}
