# Values that infra/app reads from this part.

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "servers_security_group_id" {
  value = aws_security_group.servers.id
}

output "database_address" {
  description = "DNS name of the database, reachable only from inside the VPC"
  value       = aws_db_instance.main.address
}

output "database_port" {
  value = aws_db_instance.main.port
}

output "database_name" {
  value = aws_db_instance.main.db_name
}

output "database_username" {
  value = aws_db_instance.main.username
}

output "database_password_parameter" {
  description = "Name of the Parameter Store entry that holds the password (not the password)"
  value       = aws_ssm_parameter.database_password.name
}

output "database_password_parameter_arn" {
  value = aws_ssm_parameter.database_password.arn
}
