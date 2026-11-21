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

# C25 (BP-SG-DESCRIPTION): grupo de seguridad sin description
resource "aws_security_group" "aplicacion" {
  name   = "aplicacion-ipv6-sg"
  vpc_id = aws_vpc.principal.id
}

# C23 (CIS-5.3): puerto 22 abierto a ::/0 (description constante en V y S para aislar C25)
resource "aws_security_group_rule" "ssh_ipv6" {
  type              = "ingress"
  description       = "Acceso SSH IPv6"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.aplicacion.id
}

# C24 (CIS-5.4): grupo de seguridad predeterminado de la VPC permite trafico
resource "aws_default_security_group" "predeterminado" {
  vpc_id = aws_vpc.principal.id

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
