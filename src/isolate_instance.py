import json
import datetime
import sys
import boto3
import time
import logging
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    instance_id=event['instance_id']
    region=event['region']
    aws_account=event['aws_account']
    logs_bucket=event['logs_bucket']
    associated_role=""
    #sns_topic=event['sns_topic']
    
    print("Running isolate_instance().. ")
    #deassociate instance profile
    client = boto3.client('ec2')
    response = client.describe_iam_instance_profile_associations(
        Filters=[
           {
            'Name': 'instance-id',
            'Values': [
                instance_id
            ]
        }
        ]
    )
    if response['IamInstanceProfileAssociations'] :
        association_id = response['IamInstanceProfileAssociations'][0]['AssociationId']
        associated_role = response['IamInstanceProfileAssociations'][0]['IamInstanceProfile']['Arn']
        #Disassociate
        response = client.disassociate_iam_instance_profile(
            AssociationId=association_id
            )
        print("Instance associated role:" + associated_role)
        print("Instance profile disassociated!")

    #create_ir_security_group()
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(instance_id)
    print("ASG identified: ")
    print ("vpc_id identified: %s" %(instance.vpc_id))
    old_sg_groups=str(instance.security_groups)
    old_sg_groups=old_sg_groups.replace("'", '"')

    #Extract ASG group name
    asg_groupName=""
    for tag in instance.tags:
        if tag['Key']=="aws:autoscaling:groupName":
            asg_groupName = tag['Value']
    
    print(asg_groupName)
    
    #Detach ASG if EXISTS
    if asg_groupName != "":
        client = boto3.client('autoscaling')
        detach_response = client.detach_instances(
            InstanceIds=[instance_id,
            ],
            AutoScalingGroupName=asg_groupName,
            ShouldDecrementDesiredCapacity=False
            )
        print(detach_response)
    try:
        #Create security group:
        group_name = "isolation-SG-%s" %(instance_id)
        sg = ec2.create_security_group(
            Description='Isolated EC2 instance',
            GroupName=group_name,
            VpcId=instance.vpc_id,
            DryRun=False
            )
    except ClientError as e:
        pass

    #Attach security Group to instance
    response = instance.modify_attribute(
        Groups=[
            sg.group_id,
        ],
    )
    #revoke egress traffic:
    response = sg.revoke_egress(
        DryRun=False,
        GroupId=sg.group_id,
        IpPermissions=[
        {
            'FromPort': 1,
            'IpProtocol': '-1',
            'IpRanges': [
            {
                'CidrIp': '0.0.0.0/0',
            },
            ],
            'ToPort': 65535,    
            },
        ],
        )
    print ("New IR Security Group created: %s" %(sg.group_id))
    
    #Create Image
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(instance_id)
    
    image = instance.create_image(
        Description='Forensics AMI',
        DryRun=False,
        Name="Isolated-Instance-%s-ami" %(instance_id),
        )
    print ("New AMI Image created: %s" %(image.image_id))

    revert_log="{\n \"revert_metadata\": [\n {\n \"type\": \"isolate_instance\",\n \"aws_account\": \"" + aws_account + "\",\n \"region\": \""+ region + "\",\n \"instance_id\": \"" + instance_id + "\",\n \"old_sg_groups\": \n\t" + str(old_sg_groups) + ",\n \"image_id\": \"" + image.image_id + "\",\n \"ir_sg_id\": \"" + sg.group_id + "\"\n }\n ]\n }\n"

    #Print Revert Log
    print(revert_log)

    #log Revert Log
    logger.info("Instance: " + instance_id + " was isolated: \n" + revert_log)

    #Save revert_log to file
    revert_log_file=save_revert_log_file(revert_log)

    #Save revert_log to S3
    upload_to_s3(revert_log_file,logs_bucket)

    #Send SNS notification

    return revert_log

def upload_to_s3(file_name,bucket_name):
    s3 = boto3.resource('s3')
    s3.meta.client.upload_file("/tmp/" + file_name,bucket_name,"isolate_instance_logs/"+ file_name)

def save_revert_log_file(revert_log):
    revert_log_file="revert_log" + '{:%Y%m%d-%H%M%S}'.format(datetime.datetime.now()) + ".json"
    with open("/tmp/" + revert_log_file, mode='w+') as file:
        file.write(revert_log)
        file.closed
    return revert_log_file
