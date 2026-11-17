# The private network (VPC): two public subnets for the load balancer and the
# servers, two private subnets for the database, one of each in each AZ.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true # the database is reached by its DNS name

  tags = { Name = "${var.project}-vpc" }
}

# The door between the VPC and the internet.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

# --- Public subnets: the load balancer and the servers -----------------------

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  availability_zone = var.availability_zones[count.index]
  cidr_block        = "10.0.${count.index + 1}.0/24" # 10.0.1.0/24, 10.0.2.0/24

  # Servers get a public IP so they can download packages without a NAT Gateway.
  # Nobody can reach them from outside: their security group only lets the
  # load balancer in.
  map_public_ip_on_launch = true

  tags = { Name = "${var.project}-public-${var.availability_zones[count.index]}" }
}

# "Everything that is not inside the VPC goes to the internet gateway."
# This one route is what makes a subnet public.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project}-public" }
}

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Private subnets: the database ------------------------------------------

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  availability_zone = var.availability_zones[count.index]
  cidr_block        = "10.0.${count.index + 11}.0/24" # 10.0.11.0/24, 10.0.12.0/24

  tags = { Name = "${var.project}-private-${var.availability_zones[count.index]}" }
}

# No route to the internet: only traffic inside the VPC.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-private" }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
