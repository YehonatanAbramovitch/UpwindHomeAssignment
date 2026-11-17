# The app's code, in a private S3 bucket. New servers download it when they start.
# Only what the app needs is uploaded: no tests, no samples, no Terraform.

locals {
  repository_root = "${path.module}/../.."

  code_files = sort(concat(
    tolist(fileset(local.repository_root, "{detector,web}/**/*.{py,html,css}")),
    ["requirements.txt"],
  ))

  # Changes whenever any uploaded file changes. It is written into the servers' start-up script, 
  # so a code change creates a new launch template version and the Auto Scaling group replaces the servers one at a time (instance refresh).
  code_version = sha1(join(",", [
    for file in local.code_files : "${file}:${filemd5("${local.repository_root}/${file}")}"
  ]))
}

resource "aws_s3_bucket" "code" {
  bucket_prefix = "${var.project}-code-" # a unique name is generated
  force_destroy = true                   # terraform destroy also removes the files
}

# The bucket is private: every kind of public access is blocked.
resource "aws_s3_bucket_public_access_block" "code" {
  bucket = aws_s3_bucket.code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "code" {
  bucket = aws_s3_bucket.code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # encrypted at rest with S3's own key, free
    }
  }
}

resource "aws_s3_object" "code" {
  for_each = toset(local.code_files)

  bucket = aws_s3_bucket.code.id
  key    = "app/${each.value}"
  source = "${local.repository_root}/${each.value}"
  etag   = filemd5("${local.repository_root}/${each.value}") # re-upload when the file changes
}
