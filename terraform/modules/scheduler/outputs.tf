output "event_rule_arn" {
  value = aws_cloudwatch_event_rule.schedule.arn
}

output "sns_topic_arn" {
  value = length(aws_sns_topic.notifications) > 0 ? aws_sns_topic.notifications[0].arn : ""
}
