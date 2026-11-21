terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "datos" {
  bucket = "ejemplo-datos-acceso-s"
}

# C10 (CIS-2.1.4): los cuatro controles de acceso publico activos
resource "aws_s3_bucket_public_access_block" "bloqueo" {
  bucket                  = aws_s3_bucket.datos.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Propiedad constante en el bucket con ACL para aislar C12
resource "aws_s3_bucket_ownership_controls" "propiedad_datos" {
  bucket = aws_s3_bucket.datos.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# C12 (BP-S3-ACL-PUBLIC): ACL privada
resource "aws_s3_bucket_acl" "acl" {
  depends_on = [aws_s3_bucket_ownership_controls.propiedad_datos]
  bucket     = aws_s3_bucket.datos.id
  acl        = "private"
}

# C11 (CIS-2.1.1) y C13 (BP-S3-PUBLIC-POLICY): transporte TLS obligatorio y acceso acotado a un rol
data "aws_iam_policy_document" "politica" {
  statement {
    sid     = "DenegarTransporteNoSeguro"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.datos.arn,
      "${aws_s3_bucket.datos.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "LecturaRestringidaARol"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/lector-aplicacion"]
    }
    resources = ["${aws_s3_bucket.datos.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "politica" {
  bucket = aws_s3_bucket.datos.id
  policy = data.aws_iam_policy_document.politica.json
}

# C14 (BP-S3-OWNERSHIP): BucketOwnerEnforced (ACLs deshabilitadas segun recomendacion de AWS)
resource "aws_s3_bucket" "propiedad" {
  bucket = "ejemplo-datos-propiedad-s"
}

resource "aws_s3_bucket_ownership_controls" "propiedad" {
  bucket = aws_s3_bucket.propiedad.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
