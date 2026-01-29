provider "aws" {
  region = var.region
}

variable "region" { default = "us-east-1" }

resource "aws_s3_bucket" "raw_events" {
  bucket = "${var.prefix}-soc-raw-events"
  acl    = "private"
}