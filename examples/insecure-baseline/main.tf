# NOT PART OF THE DEPLOYABLE LANDING ZONE.
#
# This is a deliberately-insecure Terraform snippet, kept only so the CI
# scanners (tfsec/Checkov) can be run against it once to produce a "before"
# baseline for docs/architecture.md and docs/scan-results/before/ - showing
# the kind of findings the hardened terraform/ configuration in this repo
# was designed to avoid. It is never applied and is excluded from the
# terraform-security-scan.yml workflow's scan path (terraform/ only).

resource "aws_security_group" "bad_ssh_open" {
  name        = "bad-ssh-open"
  description = "Wide open SSH from the internet"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere too, why not"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "bad_public_bucket" {
  bucket = "example-insecure-bucket"
}

resource "aws_s3_bucket_public_access_block" "bad_public_bucket" {
  bucket                  = aws_s3_bucket.bad_public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_ebs_volume" "bad_unencrypted" {
  availability_zone = "eu-west-3a"
  size              = 50
  encrypted         = false
}

resource "aws_iam_policy" "bad_wildcard_policy" {
  name = "bad-wildcard-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "bad_unencrypted_db" {
  identifier          = "bad-unencrypted-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "hardcoded-password-123" # also a secret committed in plaintext
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = true
}
