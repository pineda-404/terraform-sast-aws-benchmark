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
  bucket = "ejemplo-datos-cifrado-s"
}

resource "aws_s3_bucket" "logs" {
  bucket = "ejemplo-datos-logs-s"
}

# Clave KMS simetrica en ambas variantes (no es control evaluado; soporte de C15)
resource "aws_kms_key" "s3" {
  description         = "Clave KMS con rotacion automatica"
  enable_key_rotation = true
}

# C15 (BP-S3-KMS): cifrado SSE-KMS gestionado por el cliente
resource "aws_s3_bucket_server_side_encryption_configuration" "cifrado" {
  bucket = aws_s3_bucket.datos.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# C16 (BP-S3-VERSIONING) y C17 (CIS-2.1.2): versionado activo y MFA Delete habilitado
resource "aws_s3_bucket_versioning" "versionado" {
  bucket = aws_s3_bucket.datos.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

# C18 (BP-S3-ACCESS-LOGGING): registro de acceso habilitado hacia bucket de logs
resource "aws_s3_bucket_logging" "auditoria" {
  bucket        = aws_s3_bucket.datos.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}
