# Production infrastructure (AWS)

# Backups bucket — private, with public access fully blocked.
resource "aws_s3_bucket" "backups" {
  bucket = "corp-prod-backups"
}

resource "aws_s3_bucket_acl" "backups" {
  bucket = aws_s3_bucket.backups.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
