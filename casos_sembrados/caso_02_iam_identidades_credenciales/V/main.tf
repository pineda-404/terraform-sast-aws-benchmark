terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# C05 (CIS-1.15): politica adjunta directamente al usuario IAM
resource "aws_iam_user" "desarrollador" {
  name = "desarrollador-app"
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

resource "aws_iam_user_policy_attachment" "directa" {
  user       = aws_iam_user.desarrollador.name
  policy_arn = aws_iam_policy.lectura_s3.arn
}

# C06 (CIS-1.8), C07 (CIS-1.9), C08 (BP-IAM-PASSWORD-COMPLEXITY): politica debil de contrasenas
resource "aws_iam_account_password_policy" "politica" {
  minimum_password_length        = 8
  password_reuse_prevention      = 1
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  max_password_age               = 0
  allow_users_to_change_password = true
}

# C09 (BP-IAM-TRUST-WILDCARD): politica de confianza con Principal AWS = "*"
data "aws_iam_policy_document" "confianza" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "servicio" {
  name               = "rol-servicio-app"
  assume_role_policy = data.aws_iam_policy_document.confianza.json
}
