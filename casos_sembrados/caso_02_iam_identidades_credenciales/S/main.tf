terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# C05 (CIS-1.15): permisos asignados mediante grupo IAM
resource "aws_iam_user" "desarrollador" {
  name = "desarrollador-app"
}

resource "aws_iam_group" "desarrolladores" {
  name = "grupo-desarrolladores-app"
}

resource "aws_iam_user_group_membership" "membresia" {
  user   = aws_iam_user.desarrollador.name
  groups = [aws_iam_group.desarrolladores.name]
}

data "aws_iam_policy_document" "lectura_s3" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ejemplo-artefactos-app/*"]
  }
}

resource "aws_iam_policy" "lectura_s3" {
  name   = "lectura-artefactos-s3"
  policy = data.aws_iam_policy_document.lectura_s3.json
}

resource "aws_iam_group_policy_attachment" "por_grupo" {
  group      = aws_iam_group.desarrolladores.name
  policy_arn = aws_iam_policy.lectura_s3.arn
}

# C06 (CIS-1.8), C07 (CIS-1.9), C08 (BP-IAM-PASSWORD-COMPLEXITY): politica conforme a CIS v3.0.0
resource "aws_iam_account_password_policy" "politica" {
  minimum_password_length        = 14
  password_reuse_prevention      = 24
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  max_password_age               = 90
  allow_users_to_change_password = true
}

# C09 (BP-IAM-TRUST-WILDCARD): politica de confianza restringida al servicio EC2
data "aws_iam_policy_document" "confianza" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "servicio" {
  name               = "rol-servicio-app"
  assume_role_policy = data.aws_iam_policy_document.confianza.json
}
