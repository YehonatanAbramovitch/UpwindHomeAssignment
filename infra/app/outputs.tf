# What is printed at the end of `terraform apply`.

output "site_url" {
  description = "The site, through the load balancer"
  value       = "http://${aws_lb.main.dns_name}"
}

output "dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "log_group" {
  description = "Where the app logs are, in CloudWatch Logs"
  value       = aws_cloudwatch_log_group.app.name
}

output "code_bucket" {
  value = aws_s3_bucket.code.id
}

output "code_version" {
  description = "Changes when the uploaded code changes"
  value       = local.code_version
}
