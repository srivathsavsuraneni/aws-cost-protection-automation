# AWS Cost-Protection Automation

## Overview
This project implements a serverless, budget-responsive cost protection system on AWS that detects sudden spending spikes and triggers automated, safe remediation actions. It helps prevent unexpected cloud bills by continuously monitoring costs and reacting in near real time.

---

## Problem Statement
Cloud environments can experience unexpected cost spikes due to idle, misconfigured, or orphaned resources. Manual monitoring and cleanup is slow and error-prone, often leading to delayed action and higher bills.

---

## Solution
A fully serverless automation pipeline that:
1. Monitors AWS spend using AWS Budgets
2. Publishes alerts via Amazon SNS
3. Processes events using AWS Lambda (Python)
4. Evaluates resource metadata and usage patterns
5. Identifies safe cleanup candidates
6. Provides visibility through Amazon CloudWatch dashboards

---

## Architecture
**AWS Budgets → Amazon SNS → AWS Lambda (Python) → AWS Resource APIs → Amazon CloudWatch**

The system reacts automatically to budget threshold breaches and analyzes cost trends, idle indicators, and resource metadata before determining cleanup actions.

---

## AWS Services Used
- AWS Budgets  
- Amazon SNS  
- AWS Lambda (Python)  
- Amazon EC2  
- Elastic Load Balancers  
- Amazon EBS  
- NAT Gateways  
- Elastic IPs  
- Amazon CloudWatch  
- AWS IAM  

---

## Key Features
- Budget-driven automation (event-based, not polling)
- Serverless and cost-efficient architecture
- Safe cleanup logic for unused or idle resources
- Cost visibility and anomaly detection dashboards
- Reduced manual review effort and faster decision-making

---

## How It Works
1. AWS Budgets detects a cost threshold breach  
2. An SNS notification is triggered  
3. Lambda processes the event and analyzes:
   - Resource usage patterns  
   - Cost trends  
   - Idle resource indicators  
4. Safe cleanup candidates are identified (non-production, unattached, or idle resources)  
5. CloudWatch dashboards provide real-time cost visibility and diagnostics  

---

## Safety Considerations
- No hard-coded credentials or secrets
- IAM permissions follow the principle of least privilege
- Cleanup actions are designed to avoid production-critical resources
- Logic can be extended to require manual approval before deletion

---

## Use Cases
- Cost governance for personal or sandbox AWS accounts  
- Learning project for AWS automation and serverless design  
- Foundation for enterprise-grade cost optimization solutions  

---

## Future Enhancements
- Approval workflow using AWS Step Functions  
- Integration with AWS Cost Anomaly Detection  
- Tag-based enforcement for production vs non-production resources  

---

## Author
**Srivathsav Suraneni**  
AWS Certified Machine Learning Engineer – Associate
