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

# Security group scoped to HTTPS from within the private network only.
resource "aws_security_group" "open" {
  name = "restricted-ingress"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# VULN 3: Unencrypted, publicly accessible RDS with a hardcoded master password.
resource "aws_db_instance" "prod" {
  engine              = "postgres"
  instance_class      = "db.t3.large"
  username            = "admin"
  password            = "SuperSecret123!" # hardcoded secret committed to source
  storage_encrypted   = false             # no encryption at rest
  publicly_accessible = true              # reachable from the internet
}

# VULN 4: Unencrypted EBS volume.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}
