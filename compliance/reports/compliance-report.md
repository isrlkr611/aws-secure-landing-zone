# Compliance Mapping Report

Generated from a real `checkov -d terraform/` scan of this repo's infrastructure code, cross-referenced against `compliance/mapping_norms.yaml`. Not a substitute for a formal audit - see `compliance/README.md` for methodology and limitations.

**Underlying scan**: 194 passed, 0 failed, 7 skipped (75 resources, Checkov 3.3.8).

## Compliance by framework

| Framework | Compliance | Evaluated | Passed | Failed | Documented exceptions |
|---|---|---|---|---|---|
| ISO/IEC 27001:2022 (Annex A) | **100.0%** | 194 | 194 | 0 | 7 |
| NIS2 Directive (Art. 21(2)) | **100.0%** | 162 | 162 | 0 | 6 |
| PCI-DSS v4.0 | **100.0%** | 162 | 162 | 0 | 6 |
| SOC 2 (Trust Services Criteria) | **100.0%** | 162 | 162 | 0 | 6 |

"Documented exceptions" are checks Checkov flagged that were reviewed and explicitly accepted in the code (`checkov:skip=...` with an inline justification - see `docs/architecture.md` "Security Choices"). They are **not** counted toward the compliance percentage above; an auditor would need to review each one as a compensating control, which is exactly why they're broken out separately rather than folded into "passed".

## Documented exceptions requiring compensating-control review

- `CKV_AWS_382` (module.eks.aws_security_group_rule.cluster_egress_all): see justification above - NAT-gated egress from a private-subnet-only ENI, not a public exposure.
- `CKV_AWS_382` (module.eks.aws_security_group_rule.nodes_egress_all): see justification above - NAT-gated egress from a private-subnet-only ENI, not a public exposure.
- `CKV_AWS_355` (module.iam.aws_iam_role_policy.github_actions_deploy): Resource "*" appears only on the ReadOnlyDescribeUnavoidablyUnscoped, ManageVpcNetworking, and kms:CreateKey statements below, each commented with why AWS's IAM model doesn't support resource-level scoping for those specific actions. Every other statement is scoped to a name-prefixed or explicit ARN.
- `CKV_AWS_274` (module.iam.aws_iam_role_policy_attachment.break_glass_admin): intentional break-glass role, not day-to-day access.
- `CKV_AWS_352` (module.vpc.aws_network_acl_rule.private_allow_vpc_inbound): intra-VPC only (cidr_block = var.vpc_cidr), see justification above.
- `CKV_AWS_231` (module.vpc.aws_network_acl_rule.private_allow_ephemeral_inbound): this is the stateless-NACL ephemeral-port return-traffic rule, not a direct RDP allow - the dedicated deny rule for port 3389 above (rule_number 91) is evaluated first and wins.
- `CKV2_AWS_1` (module.vpc.aws_network_acl.private): subnet_ids is populated (aws_subnet.private[*].id below) - Checkov's static analysis doesn't resolve splat expressions against a count-based resource here, producing a false positive. Confirmed via `terraform plan`: every private subnet is associated.

## Coverage by control theme

- **IAM least privilege and privilege escalation prevention** - 100.0% (70/70), skipped: 2
  Maps to: ISO/IEC 27001:2022 (Annex A), PCI-DSS v4.0, NIS2 Directive (Art. 21(2)), SOC 2 (Trust Services Criteria)
- **Authentication, federation, and secret handling** - 100.0% (9/9), skipped: 0
  Maps to: ISO/IEC 27001:2022 (Annex A), PCI-DSS v4.0, NIS2 Directive (Art. 21(2)), SOC 2 (Trust Services Criteria)
- **Audit logging, retention, and monitoring** - 100.0% (6/6), skipped: 0
  Maps to: ISO/IEC 27001:2022 (Annex A), PCI-DSS v4.0, NIS2 Directive (Art. 21(2)), SOC 2 (Trust Services Criteria)
- **Encryption at rest and key management** - 100.0% (23/23), skipped: 0
  Maps to: ISO/IEC 27001:2022 (Annex A), PCI-DSS v4.0, NIS2 Directive (Art. 21(2)), SOC 2 (Trust Services Criteria)
- **Resource configuration hygiene** - 100.0% (32/32), skipped: 1
  Maps to: ISO/IEC 27001:2022 (Annex A)
- **Network segmentation and internet-facing exposure** - 100.0% (54/54), skipped: 4
  Maps to: ISO/IEC 27001:2022 (Annex A), PCI-DSS v4.0, NIS2 Directive (Art. 21(2)), SOC 2 (Trust Services Criteria)
