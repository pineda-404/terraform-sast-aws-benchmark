terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# C01 (CIS-1.16): accion acotada a solo lectura sobre bucket especifico
data "aws_iam_policy_document" "datos" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::ejemplo-datos-corporativos/lectura/*"]
  }
}

resource "aws_iam_policy" "datos" {
  name   = "ejemplo-politica-datos"
  policy = data.aws_iam_policy_document.datos.json
}

# C02 (BP-IAM-WILDCARD-RESOURCE): escritura restringida a prefijo especifico
data "aws_iam_policy_document" "escritura" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::ejemplo-datos-corporativos/cargas/*"]
  }
}

resource "aws_iam_policy" "escritura" {
  name   = "ejemplo-politica-escritura"
  policy = data.aws_iam_policy_document.escritura.json
}

# C03 (OFF-IAM-PASSROLE): iam:PassRole acotado a un rol y servicio destino
data "aws_iam_policy_document" "passrole" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::123456789012:role/ejecucion-lambda-acotada"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "passrole" {
  name   = "ejemplo-politica-passrole"
  policy = data.aws_iam_policy_document.passrole.json
}

# C04 (BP-IAM-PRIVILEGE-ESC-POLICY): solo lectura sobre politica especifica
data "aws_iam_policy_document" "gestion_politicas" {
  statement {
    effect = "Allow"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
    ]
    resources = ["arn:aws:iam::123456789012:policy/consulta-solo-lectura"]
  }
}

resource "aws_iam_policy" "gestion_politicas" {
  name   = "ejemplo-gestion-politicas"
  policy = data.aws_iam_policy_document.gestion_politicas.json
}
