# Where the web servers' logs go in CloudWatch Logs.
# It lives here, in the part that is kept, and not in infra/app: infra/app is
# destroyed at the end of every work session, and the logs must outlive the
# servers and the load balancer, like the data in the database. 
# infra/app reads the name from the outputs and the servers write into it.

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = var.log_retention_days # not "forever", the AWS default
}
