# Remote state with locking and encryption. Bootstrap the bucket/table once
# by hand (or via a separate `terraform/bootstrap` state) before pointing
# this block at them - a backend cannot be created by the same config that
# uses it.
terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_YOUR_TFSTATE_BUCKET"
    key            = "landing-zone/prod/terraform.tfstate"
    region         = "eu-west-3"
    encrypt        = true
    dynamodb_table = "REPLACE_WITH_YOUR_TF_LOCK_TABLE"
  }
}
