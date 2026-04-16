// EventBridge + SNS alerting for destructive KMS operations (PLAN.md §2.11).
// Resources to be implemented in Phase 1 next session.
// Required:
//   - aws_sns_topic.kms_alerts (talos-cluster-kms-alerts)
//   - aws_sns_topic_subscription (email to operator)
//   - aws_cloudwatch_event_rule.kms_destructive (talos-cluster-kms-alerts)
//     event_pattern matching CloudTrail API calls:
//       ScheduleKeyDeletion, DisableKey, PutKeyPolicy
//     filtered to the vault-unseal key.
//   - aws_cloudwatch_event_target wiring rule -> sns topic.
