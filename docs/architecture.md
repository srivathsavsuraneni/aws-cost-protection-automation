# Architecture

**AWS Budgets → SNS → Lambda (Python) → AWS APIs → CloudWatch**

- AWS Budgets triggers an alert when a threshold is crossed
- SNS delivers the alert to Lambda
- Lambda evaluates tagged resources and identifies safe cleanup candidates
- Actions are logged and visualized in CloudWatch dashboards

Safety:
- DRY_RUN defaults to true
- Only resources tagged `CostCleanup=true` are considered
- Resources tagged `DoNotDelete=true` are skipped
