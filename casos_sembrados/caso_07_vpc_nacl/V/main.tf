terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_vpc" "principal" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_subnet" "aplicacion" {
  vpc_id                  = aws_vpc.principal.id
  cidr_block              = "10.1.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_network_acl" "perimetral" {
  vpc_id     = aws_vpc.principal.id
  subnet_ids = [aws_subnet.aplicacion.id]
}

# C26 (CIS-5.1): NACL permite SSH (puerto 22) desde 0.0.0.0/0
resource "aws_network_acl_rule" "ssh_ingreso" {
  network_acl_id = aws_network_acl.perimetral.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

# C27 (BP-VPC-NACL-ALL-INGRESS): NACL permite todos los protocolos desde 0.0.0.0/0
resource "aws_network_acl_rule" "todos_protocolos" {
  network_acl_id = aws_network_acl.perimetral.id
  rule_number    = 110
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}
