# The role the web servers run with: exactly what they need, nothing more.
# No keys or passwords are stored on the servers: they get temporary credentials for this role automatically.

resource "aws_iam_role" "servers" {
  name = "${var.project}-servers"

  # Only EC2 instances may take this role.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Session Manager: lets an administrator open a shell without SSH or open ports.
resource "aws_iam_role_policy_attachment" "session_manager" {
  role       = aws_iam_role.servers.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch agent: lets the servers send memory, disk and log data.
resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.servers.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Read the app's code from the bucket, and read the database password
# parameter. Only these: not other buckets, not other parameters.
resource "aws_iam_role_policy" "app" {
  name = "read-code-and-database-password"
  role = aws_iam_role.servers.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAppCode"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.code.arn}/app/*"
      },
      {
        Sid       = "ListAppCode"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.code.arn
        Condition = { StringLike = { "s3:prefix" = ["app/*"] } }
      },
      {
        Sid      = "ReadDatabasePassword"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = local.base.database_password_parameter_arn
      },
    ]
  })
}

# The "badge" that connects the role to an EC2 instance.
resource "aws_iam_instance_profile" "servers" {
  name = "${var.project}-servers"
  role = aws_iam_role.servers.name
}
