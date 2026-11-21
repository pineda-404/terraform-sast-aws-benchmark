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
  bucket = "ejemplo-datos-cifrado-v"
}

resource "aws_s3_bucket" "logs" {
  bucket = "ejemplo-datos-logs-v"
}

# Clave KMS simetrica en ambas variantes (no es control evaluado; soporte de C15)
resource "aws_kms_key" "s3" {
  description         = "Clave KMS con rotacion automatica"
  enable_key_rotation = true
}

# C15 (BP-S3-KMS): solo SSE-S3 (AES256) sin KMS administrado por cliente
resource "aws_s3_bucket_server_side_encryption_configuration" "cifrado" {
  bucket = aws_s3_bucket.datos.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# C16 (BP-S3-VERSIONING) y C17 (CIS-2.1.2): versionado suspendido y sin MFA Delete
resource "aws_s3_bucket_versioning" "versionado" {
  bucket = aws_s3_bucket.datos.id
  versioning_configuration {
    status     = "Suspended"
    mfa_delete = "Disabled"
  }
}

# C18 (BP-S3-ACCESS-LOGGING): registro de acceso omitido en esta variante
