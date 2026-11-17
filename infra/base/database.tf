# The PostgreSQL database (RDS) and its password.
# This part is created in advance and kept: the demo applies and destroys only infra/app, so the scan history survives.

resource "aws_db_subnet_group" "main" {
  name        = "${var.project}-db"
  description = "Private subnets for the database (RDS requires two AZs)"
  subnet_ids  = aws_subnet.private[*].id
}

# A long random password. Letters and digits only, so it can be put into the
# DATABASE_URL connection string without escaping.
resource "random_password" "database" {
  length  = 32
  special = false
}

# The servers read the password from here when they start (only this parameter).
# Note: Terraform also keeps the password in its local state file, which is git-ignored and stays on this computer.
resource "aws_ssm_parameter" "database_password" {
  name        = "/${var.project}/database/password"
  description = "Password of the RDS master user"
  type        = "SecureString" # encrypted with the AWS managed key, free
  value       = random_password.database.result
}

resource "aws_db_instance" "main" {
  identifier = "${var.project}-db"

  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.t4g.micro" # ARM, about 11% cheaper than db.t3.micro

  allocated_storage = 20 # GB
  storage_type      = "gp3"
  storage_encrypted = true # encryption at rest

  db_name  = "phishing"
  username = "phishing_admin"
  password = random_password.database.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = false # single AZ to save half the cost; scans work without it

  backup_retention_period = 1 # one day of automatic backups
  deletion_protection     = true
  # With deletion protection on, a final snapshot is not needed to prevent an
  # accident, and skipping it keeps the final cleanup simple and free.
  skip_final_snapshot = true
  apply_immediately   = true

  tags = { Name = "${var.project}-db" }
}
