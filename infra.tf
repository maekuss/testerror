# Production infrastructure (AWS)

# VULN 1: Publicly readable S3 bucket — backup objects exposed to the internet.
resource "aws_s3_bucket" "backups" {
  bucket = "corp-prod-backups"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULN 2: Security group open to the entire internet on every port (incl. SSH).
resource "aws_security_group" "open" {
  name = "allow-all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  description = "Master password for the production RDS instance. Supply via TF_VAR_db_password or a secrets manager; never commit a literal value."
  type        = string
  sensitive   = true
}

resource "aws_db_instance" "prod" {
  engine              = "postgres"
  instance_class      = "db.t3.large"
  username            = "admin"
  password            = var.db_password # sourced from a secret, not hardcoded
  storage_encrypted   = true            # encrypt data at rest
  publicly_accessible = false           # not reachable from the internet
}

# VULN 4: Unencrypted EBS volume.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}
