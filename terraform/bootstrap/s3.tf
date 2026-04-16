// Velero backup bucket (PLAN.md §2.7, §4 Phase 1).
// Resources to be implemented in Phase 1 next session.
// Required:
//   - aws_s3_bucket.velero (793496711039-talos-cluster-velero, prevent_destroy = true)
//   - aws_s3_bucket_versioning (enabled)
//   - aws_s3_bucket_server_side_encryption_configuration (AES256)
//   - aws_s3_bucket_public_access_block (all blocks enabled)
//   - aws_s3_bucket_ownership_controls (BucketOwnerEnforced)
//   - aws_s3_bucket_lifecycle_configuration (object expiration per backup retention)
