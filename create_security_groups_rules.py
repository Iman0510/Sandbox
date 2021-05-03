import csv
import boto3

with open('security_groups.csv', 'r') as fd:
    reader = csv.DictReader(fd)
    sg_name_id={}
    result={}
    for row in reader:
        ec2_client=boto3.client('ec2', region_name=row['region'])
        print(f"Creating security group {row['name']} with description: Enable access to {row['description']} with VPC ID: {row['vpcid']} and Region: {row['region']}")
        if row['name']=='sgr-eas-prd-cloudflare-whitelist':
            result=ec2_client.create_security_group(
                Description="Enable DNS (Cloudlare) whitelist IPs",
                GroupName=row['name'],
                VpcId=row['vpcid'],
                TagSpecifications=[
                    {
                        'ResourceType': 'security-group',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': row['name']
                            }
                        ]
                    }
                ]
            )
            sg_name_id[row['name']].append(result.get("GroupId"))
        else:
            ec2_client.create_security_group(
                Description="Enable access to {} server".format(row['description']),
                GroupName=row['name'],
                VpcId=row['vpcid'],
                TagSpecifications=[
                    {
                        'ResourceType': 'security-group',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': row['name']
                            }
                        ]
                    }
                ]
            )
            sg_name_id[row['name']].append(result.get("GroupId"))

with open('security_group_rules2.csv', 'r') as fd:
    rules = csv.DictReader(fd)
    for rule in rules:
        port=int(rule['port'])
        if rule['source']=='cidr_ip':
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_name_id.get(row['name']),
                IpPermissions=[
                    {
                        'FromPort': port,
                        'ToPort': port,
                        'IpProtocol': rule['protocol'],
                        'IpRanges': [
                            {
                            'CidrIp': rule['sourcevalue'],
                            'Description': rule['description']
                            }
                        ]
                    }
                ]
            )
            print(f"Creating security rule for: {rule['name']}\n Source IP: {rule['sourcevalue']}\n Protocol and Port: {rule['protocol']} {rule['port']}\n Description: {rule['description']}\n")
        elif rule['source']=='cidr_ipv6':
            ec2_client.authorize_security_group_ingress(
                    GroupId=sg_name_id.get(row['name']),
                    IpPermissions=[
                        {
                            'FromPort': port,
                            'ToPort': port,
                            'IpProtocol': rule['protocol'],
                            'Ipv6Ranges': [
                                {
                                'CidrIpv6': rule['sourcevalue'],
                                'Description': rule['description']
                                }
                            ]
                        }
                    ]
                )
            print(f"Creating security rule for: {rule['name']}\n Source IPv6: {rule['sourcevalue']}\n Protocol and Port: {rule['protocol']} {rule['port']}\n Description: {rule['description']}\n")
        else:
            ec2_client.authorize_security_group_ingress(
                    GroupId=sg_name_id.get(row['name']),
                    IpPermissions=[
                        {
                            'FromPort': port,
                            'ToPort': port,
                            'IpProtocol': rule['protocol'],
                            'UserIdGroupPairs': [
                                {
                                'GroupName': rule['sourcevalue'],
                                'Description': rule['description']
                                }
                            ]
                        }
                    ]
                )
            print(f"Creating security rule for: {rule['name']}\n Source SG: {rule['sourcevalue']}\n Protocol and Port: {rule['protocol']} {rule['port']}\n Description: {rule['description']}\n")