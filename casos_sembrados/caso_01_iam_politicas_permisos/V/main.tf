terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# C01 (CIS-1.16): Action = ["*"] sobre todos los recursos
data "aws_iam_policy_document" "datos" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "datos" {
  name   = "ejemplo-politica-datos"
  policy = data.aws_iam_policy_document.datos.json
}

# C02 (BP-IAM-WILDCARD-RESOURCE): accion de escritura con Resource = ["*"]
data "aws_iam_policy_document" "escritura" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "escritura" {
  name   = "ejemplo-politica-escritura"
  policy = data.aws_iam_policy_document.escritura.json
}

# C03 (OFF-IAM-PASSROLE): iam:PassRole sin restriccion de recurso
data "aws_iam_policy_document" "passrole" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "passrole" {
  name   = "ejemplo-politica-passrole"
  policy = data.aws_iam_policy_document.passrole.json
}

# C04 (BP-IAM-PRIVILEGE-ESC-POLICY): modificacion de versiones de politicas sin restriccion
data "aws_iam_policy_document" "gestion_politicas" {
  statement {
    effect = "Allow"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "gestion_politicas" {
  name   = "ejemplo-gestion-politicas"
  policy = data.aws_iam_policy_document.gestion_politicas.json
}
