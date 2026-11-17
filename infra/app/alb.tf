# The Application Load Balancer: the only address users know. 
# It spreads requests over the two servers and stops sending to a server that fails its health check.

resource "aws_security_group" "alb" {
  name        = "${var.project}-alb"
  description = "Load balancer: HTTP from the internet, out only to the web servers"
  vpc_id      = local.base.vpc_id

  tags = { Name = "${var.project}-alb" }
}

# HTTP only: there is no domain for an HTTPS certificate (a known limitation).
resource "aws_vpc_security_group_ingress_rule" "alb_http_from_internet" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_servers" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Requests and health checks to the web servers"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = local.base.servers_security_group_id
}

# The rule that lets the load balancer into the servers. It is added to the
# servers' security group from infra/base, and removed with the load balancer.
resource "aws_vpc_security_group_ingress_rule" "servers_from_alb" {
  security_group_id            = local.base.servers_security_group_id
  description                  = "App port from the load balancer only"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_lb" "main" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false # reachable from the internet
  subnets            = local.base.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]

  drop_invalid_header_fields = true # reject malformed HTTP headers
}

resource "aws_lb_target_group" "servers" {
  name     = "${var.project}-servers"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = local.base.vpc_id

  # When a server leaves (replaced or removed), wait 30 seconds for its open requests.
  deregistration_delay = 30

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = var.health_check_interval_seconds
    timeout             = 5
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.servers.arn
  }
}
