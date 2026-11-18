# Monitoring: where the logs go, two alarms by email, and one dashboard that
# answers the assignment's questions: are the servers healthy, how much CPU
# and memory they use, how many requests reach the load balancer, whether
# they succeed or fail, and where the app logs are.

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = var.log_retention_days # not "forever", the AWS default
}

# --- Alarms, by email -------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

# AWS sends a confirmation email first: the link in it must be clicked once.
resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  alb_dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.servers.arn_suffix
  }
}

# Fewer than two healthy servers: the site still works, but without a spare.
# Also emails when it is back to two (the Auto Scaling group replaced the server).
resource "aws_cloudwatch_metric_alarm" "healthy_servers" {
  alarm_name          = "${var.project}-fewer-than-2-healthy-servers"
  alarm_description   = "Fewer than 2 web servers pass the load balancer health check"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = local.alb_dimensions
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "LessThanThreshold"
  threshold           = 2
  treat_missing_data  = "breaching" # no data at all is also a problem
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# The app itself returns errors (5xx), even though the servers are up.
resource "aws_cloudwatch_metric_alarm" "server_errors" {
  alarm_name          = "${var.project}-server-errors"
  alarm_description   = "The web servers returned at least one 5xx response in a minute"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = local.alb_dimensions
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  # From the first error: traffic is low, and every app 5xx means something is
  # really wrong (a bug, or the database is unavailable).
  threshold          = 0
  treat_missing_data = "notBreaching" # no errors reported means no errors
  alarm_actions      = [aws_sns_topic.alerts.arn]
  ok_actions         = [aws_sns_topic.alerts.arn]
}

# --- Dashboard --------------------------------------------------------------

locals {
  alb    = aws_lb.main.arn_suffix
  target = aws_lb_target_group.servers.arn_suffix
  asg    = aws_autoscaling_group.servers.name

  # One graph on the dashboard.
  graph = {
    width  = 12
    height = 6
    type   = "metric"
  }
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.project

  dashboard_body = jsonencode({
    widgets = [
      merge(local.graph, { x = 0, y = 0, properties = {
        title  = "Are the servers healthy? (load balancer health check)"
        region = var.region
        period = 60
        stat   = "Minimum"
        metrics = [
          ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", local.target, "LoadBalancer", local.alb],
          ["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", local.target, "LoadBalancer", local.alb],
        ]
      } }),
      merge(local.graph, { x = 12, y = 0, properties = {
        title   = "How many requests reach the load balancer?"
        region  = var.region
        period  = 60
        stat    = "Sum"
        metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb]]
      } }),
      merge(local.graph, { x = 0, y = 6, properties = {
        title  = "Do requests succeed or fail? (responses by code)"
        region = var.region
        period = 60
        stat   = "Sum"
        metrics = [
          ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "TargetGroup", local.target, "LoadBalancer", local.alb, { label = "2xx success" }],
          ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "TargetGroup", local.target, "LoadBalancer", local.alb, { label = "4xx rejected input" }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "TargetGroup", local.target, "LoadBalancer", local.alb, { label = "5xx app error" }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb, { label = "5xx from the load balancer" }],
        ]
      } }),
      merge(local.graph, { x = 12, y = 6, properties = {
        title   = "How long does a response take? (seconds)"
        region  = var.region
        period  = 60
        stat    = "Average"
        metrics = [["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb]]
      } }),
      merge(local.graph, { x = 0, y = 12, properties = {
        title   = "How much CPU do the servers use? (%)"
        region  = var.region
        period  = 300
        stat    = "Average"
        metrics = [["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", local.asg]]
      } }),
      merge(local.graph, { x = 12, y = 12, properties = {
        title  = "Memory and disk used on the servers (%)"
        region = var.region
        period = 60
        stat   = "Average"
        metrics = [
          [var.project, "mem_used_percent", "AutoScalingGroupName", local.asg, { label = "memory" }],
          [var.project, "disk_used_percent", "AutoScalingGroupName", local.asg, { label = "disk /" }],
        ]
      } }),
      merge(local.graph, { x = 0, y = 18, properties = {
        title  = "Database: CPU (%) and open connections"
        region = var.region
        period = 300
        stat   = "Average"
        metrics = [
          ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", local.base.database_identifier, { label = "CPU %" }],
          ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", local.base.database_identifier, { label = "connections", yAxis = "right" }],
        ]
      } }),
      {
        type   = "log"
        x      = 12
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "Where are the app logs? Latest scans and errors (log group ${aws_cloudwatch_log_group.app.name})"
          region = var.region
          query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, @logStream, @message | filter @message like /scan score|ERROR|Database unavailable/ | sort @timestamp desc | limit 50"
          view   = "table"
        }
      },
    ]
  })
}
