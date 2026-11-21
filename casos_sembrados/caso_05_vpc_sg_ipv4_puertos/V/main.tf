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
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "administracion" {
  name        = "administracion-sg"
  description = "Grupo de seguridad para pruebas de reglas IPv4"
  vpc_id      = aws_vpc.principal.id
}

# C19 (CIS-5.2): SSH puerto 22 abierto a 0.0.0.0/0
resource "aws_security_group_rule" "ssh_ipv4" {
  type              = "ingress"
  description       = "Acceso SSH"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.administracion.id
}

# C20 (CIS-5.2): RDP puerto 3389 abierto a 0.0.0.0/0
resource "aws_security_group_rule" "rdp_ipv4" {
  type              = "ingress"
  description       = "Acceso RDP"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.administracion.id
}

# C21 (BP-SG-ALL-PROTOCOLS): ingreso con protocol = "-1" abierto a 0.0.0.0/0
resource "aws_security_group_rule" "todos_protocolos" {
  type              = "ingress"
  description       = "Todos los protocolos"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.administracion.id
}

# C22 (BP-SG-EGRESS-OPEN): salida sin restricciones a 0.0.0.0/0
resource "aws_security_group_rule" "salida" {
  type              = "egress"
  description       = "Salida abierta"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.administracion.id
}
