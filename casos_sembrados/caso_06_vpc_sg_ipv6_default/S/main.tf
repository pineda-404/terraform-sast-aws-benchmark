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
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true
}

# C25 (BP-SG-DESCRIPTION): grupo de seguridad con description explicita
resource "aws_security_group" "aplicacion" {
  name        = "aplicacion-ipv6-sg"
  description = "Grupo de seguridad con reglas IPv6 restringidas"
  vpc_id      = aws_vpc.principal.id
}

# C23 (CIS-5.3): puerto 22 restringido a prefijo IPv6 privado
resource "aws_security_group_rule" "ssh_ipv6" {
  type              = "ingress"
  description       = "Acceso SSH IPv6"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["fd00::/64"]
  security_group_id = aws_security_group.aplicacion.id
}

# C24 (CIS-5.4): grupo de seguridad predeterminado vacio restringe todo trafico
resource "aws_default_security_group" "predeterminado" {
  vpc_id = aws_vpc.principal.id
}
