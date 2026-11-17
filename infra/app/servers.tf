# The two web servers: a launch template that describes one server, and an
# Auto Scaling group that always keeps two of them, one in each AZ.

# The latest Amazon Linux 2023 image, from AWS's public parameter.
data "aws_ssm_parameter" "amazon_linux" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_launch_template" "servers" {
  name                   = "${var.project}-servers"
  image_id               = data.aws_ssm_parameter.amazon_linux.value
  instance_type          = var.instance_type
  vpc_security_group_ids = [local.base.servers_security_group_id]
  update_default_version = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.servers.arn
  }

  # Instance metadata only with session tokens (IMDSv2). This blocks a common
  # way to steal the server's credentials through a request forgery bug.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  # The start-up script: installs and starts the app (see user_data.sh.tftpl).
  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    region                  = var.region
    project                 = var.project
    app_port                = var.app_port
    code_bucket             = aws_s3_bucket.code.id
    code_version            = local.code_version
    database_host           = local.base.database_address
    database_port           = local.base.database_port
    database_name           = local.base.database_name
    database_user           = local.base.database_username
    database_password_param = local.base.database_password_parameter
    log_group               = aws_cloudwatch_log_group.app.name
  }))

  # The provider's default tags do not reach instances that the Auto Scaling
  # group launches, so they are set here explicitly, also on their disks.
  dynamic "tag_specifications" {
    for_each = ["instance", "volume", "network-interface"]
    content {
      resource_type = tag_specifications.value
      tags = {
        Name    = "${var.project}-server"
        Project = var.project
      }
    }
  }
}

resource "aws_autoscaling_group" "servers" {
  name                = "${var.project}-servers"
  min_size            = 2
  max_size            = 2
  desired_capacity    = 2
  vpc_zone_identifier = local.base.public_subnet_ids # one subnet in each AZ
  target_group_arns   = [aws_lb_target_group.servers.arn]

  # Replace a server that fails the load balancer's health check, not only one
  # whose machine stopped. A new server gets 5 minutes to install before checks count.
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.servers.id
    version = aws_launch_template.servers.latest_version
  }

  # A new launch template version (for example new code) replaces the servers
  # one at a time, so one server always keeps answering.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-server"
    propagate_at_launch = true
  }

  tag {
    key                 = "Project"
    value               = var.project
    propagate_at_launch = true
  }

  # The code must be in the bucket before the first server starts.
  depends_on = [aws_s3_object.code]
}
