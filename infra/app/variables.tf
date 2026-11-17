# The values this part of the infrastructure can be configured with.

variable "region" {
  description = "AWS region; must be the same as in infra/base."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name, used in resource names and in the Project tag."
  type        = string
  default     = "phishing-detector"
}

variable "alert_email" {
  description = "Email address for the CloudWatch alarms. Set it in terraform.tfvars (not in Git)."
  type        = string
}

variable "instance_type" {
  description = "Size of the two web servers."
  type        = string
  default     = "t3.micro"
}

variable "app_port" {
  description = "Port the app listens on inside the servers (gunicorn)."
  type        = number
  default     = 8000
}

# Load balancer health check: a server leaves after about 20 seconds of
# failures, and comes back after about 20 seconds of successes.
variable "health_check_interval_seconds" {
  type    = number
  default = 10
}

variable "health_check_unhealthy_threshold" {
  type    = number
  default = 2
}

variable "health_check_healthy_threshold" {
  type    = number
  default = 2
}

variable "log_retention_days" {
  description = "How long CloudWatch keeps the app logs."
  type        = number
  default     = 30
}
