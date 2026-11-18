# The channel that the CloudWatch alarms in infra/app send their emails to.
# It lives here, in the part that is kept: an email subscription must be
# confirmed by clicking a link, and if it were recreated with every apply of
# infra/app, every apply would need a new confirmation, and the alarms would
# send no email until then. Here it is confirmed once.

resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

# AWS sends a confirmation email first: the link in it must be clicked once.
resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
