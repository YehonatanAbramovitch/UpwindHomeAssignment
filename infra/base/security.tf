# Security groups (firewalls) that live with the database.
#
# The rings: internet -> load balancer (80) -> servers (8000) -> database (5432).
# The load balancer's group and the rule that lets it reach the servers are in
# infra/app, because they are created and removed with the load balancer.

resource "aws_security_group" "servers" {
  name        = "${var.project}-servers"
  description = "Web servers: inbound only from the load balancer (rule in infra/app)"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project}-servers" }
}

# Servers may go out to the internet: packages, CloudWatch, Session Manager.
# Restricting it would still have to leave port 443 open, which is also what
# harmful traffic would use, so the gain is small and the risk of a broken
# install is real.
resource "aws_vpc_security_group_egress_rule" "servers_all_out" {
  security_group_id = aws_security_group.servers.id
  description       = "All outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "database" {
  name        = "${var.project}-database"
  description = "PostgreSQL: inbound only from the web servers, no outbound"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project}-database" }
}

resource "aws_vpc_security_group_ingress_rule" "database_from_servers" {
  security_group_id            = aws_security_group.database.id
  description                  = "PostgreSQL from the web servers only"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.servers.id
}

# The database group has no outbound rule at all: Terraform removes the default
# "allow all outbound" rule, and the database never needs to start a connection.
