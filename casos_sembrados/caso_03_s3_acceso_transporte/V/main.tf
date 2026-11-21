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
  bucket = "ejemplo-datos-acceso-v"
}

# C10 (CIS-2.1.4): bloqueo de acceso publico deshabilitado
resource "aws_s3_bucket_public_access_block" "bloqueo" {
  bucket                  = aws_s3_bucket.datos.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Propiedad constante en el bucket con ACL para aislar C12
resource "aws_s3_bucket_ownership_controls" "propiedad_datos" {
  bucket = aws_s3_bucket.datos.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# C12 (BP-S3-ACL-PUBLIC): ACL de lectura publica
resource "aws_s3_bucket_acl" "acl" {
  depends_on = [aws_s3_bucket_ownership_controls.propiedad_datos]
  bucket     = aws_s3_bucket.datos.id
  acl        = "public-read"
}

# C11 (CIS-2.1.1) y C13 (BP-S3-PUBLIC-POLICY): sin denegacion HTTP y Allow con Principal = "*"
data "aws_iam_policy_document" "politica" {
  statement {
    sid     = "LecturaPublicaSinTLS"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.datos.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "politica" {
  bucket = aws_s3_bucket.datos.id
  policy = data.aws_iam_policy_document.politica.json
}

# C14 (BP-S3-OWNERSHIP): bucket dedicado sin ACL para evaluar ObjectWriter vs BucketOwnerEnforced
resource "aws_s3_bucket" "propiedad" {
  bucket = "ejemplo-datos-propiedad-v"
}

resource "aws_s3_bucket_ownership_controls" "propiedad" {
  bucket = aws_s3_bucket.propiedad.id
  rule {
    object_ownership = "ObjectWriter"
  }
}
