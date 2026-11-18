# The values this part of the infrastructure can be configured with.

variable "region" {
  description = "AWS region for everything in the project."
  type        = string
  # The account's project only allows this region (a service control policy
  # denies the others), so everything runs in Stockholm.
  default = "eu-north-1"
}

variable "project" {
  description = "Project name, used in resource names and in the Project tag."
  type        = string
  default     = "phishing-detector"
}

variable "availability_zones" {
  description = "Two Availability Zones: one server and one subnet of each kind in each."
  type        = list(string)
  default     = ["eu-north-1a", "eu-north-1b"]
}

variable "alert_email" {
  description = "Email address for the budget alerts. Set it in terraform.tfvars (not in Git)."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly cost after which the budget alert emails are sent (at 50% and 100%)."
  type        = number
  default     = 10
}
