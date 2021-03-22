# isolate_instance
Lambda function to contain compromised EC2 instances 

# Deployment

# Execution
aws lambda invoke --function-name arn.... --payload \
    '{ 
        "instance_id":"i-xxxxxxx",
        "region": "us-east-1",
        "aws_account": "xxxxxxxxxxx",
        "logs_bucket": "bucketxxxxxxxx"
        }' \
        lambda_out.txt --region us-east-1
