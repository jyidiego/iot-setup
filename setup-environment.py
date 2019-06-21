#!/usr/bin/env python

import boto3
import re
import sys
from botocore.config import Config
from jinja2 import Environment, FileSystemLoader


wifi_ssid = 'foo'
wifi_password = '12345'

config = Config(
    retries = dict(
        max_attempts = 10
        )
    )


def create_ESP32_thing_type(client):
    if 'ESP32-Things' not in [ i['thingTypeName'] for i in client.list_thing_types()['thingTypes'] ]:
        return client.create_thing_type(thingTypeName='ESP32-Things',tags=[{'Key': 'Purpose', 'Value' : 'Demo'}])
    else:
        print("ESP32-Things already exists.")
        return [ i for i in client.list_thing_types()['thingTypes'] if 'ESP32-Things' == i['thingTypeName'] ][0]


def create_IoT_TemperatureSensors_group(client):
    if 'TemperatureSensors' not in [ i['groupName'] for i in client.list_thing_groups()['thingGroups'] ]:
        return client.create_thing_group(   thingGroupName='TemperatureSensors', \
                                            thingGroupProperties={  'thingGroupDescription' : '', \
                                                                    'attributePayload' : { 'attributes' : { 'Core' : 'ESP32', 'Sensor' : 'DHT22'} }})
    else:
        print("TemperatureSensors group already exists.")
        return [ i for i in client.list_thing_groups()['thingGroups'] if 'TemperatureSensors' == i['groupName'] ][0]


def create_IoT_thing(client):
    if 'IoT-Temperature-Device' not in [ i['thingName'] for i in client.list_things()['things'] ]:
        return client.create_thing(thingName='IoT-Temperature-Device',thingTypeName='ESP32-Things')
    else:
        print("IoT-Temperature-Device already exists.")
        return [ i for i in client.list_things()['things'] if 'IoT-Temperature-Device' == i['thingName'] ][0]
        

def select_thing_group_keys(thing_group):
    if thing_group.has_key('thingGroupName'):
        kn = 'thingGroupName'
        ka = 'thingGroupArn'
    elif thing_group.has_key('groupName'):
        kn = 'groupName'
        ka = 'groupArn'
    return (kn,ka)


def add_thing_to_group(client, thing, thing_group):
        print("thing_group: {}".format(thing_group))
        print("thing: {}".format(thing))
        thing_groups_for_thing = client.list_thing_groups_for_thing(thingName=thing['thingName'])
        print("thing_group_for_thing: {}".format(thing_groups_for_thing))
        if not thing_groups_for_thing['thingGroups']:
            client.add_thing_to_thing_group(    thingGroupName=thing_group[select_thing_group_keys(thing_group)[0]],\
                                                thingGroupArn=thing_group[select_thing_group_keys(thing_group)[1]],\
                                                thingName=thing['thingName'],\
                                                thingArn=thing['thingArn'] )
        else:
            print("Thing {} is already been added to {}".format(thing, thing_group))


def create_policy(client, thing_group):
    if 'TemperatureSensorPolicy' not in [ i['policyName'] for i in client.list_policies()['policies'] ]:
        policy = client.create_policy(    policyName='TemperatureSensorPolicy',\
                                        policyDocument='{   "Version" : "2012-10-17",\
                                                            "Statement":\
                                                                [ { "Effect" : "Allow",\
                                                                    "Action" : "iot:*",\
                                                                    "Resource" : "*"} ]}'   )
        attach_policy(client, policy=policy, thing_group=thing_group)
    else:
        print("TemperatureSensorPolicy already exists.")


def attach_policy(client, policy, thing_group):
    print("thing_group: {}".format(thing_group))
    client.attach_policy(policyName=policy['policyName'], target=thing_group[select_thing_group_keys(thing_group)[1]])


def create_certificates(client):
    return client.create_keys_and_certificate(setAsActive=True)

    
def create_iot_code_bucket(s3_client, sts_client):
    bucket_name = "iot-code-{}-1".format(sts_client.get_caller_identity()['Account'])
    if bucket_name not in [ i['Name'] for i in s3_client.list_buckets()['Buckets']]:
        # return s3_client.create_bucket(Bucket="iot-code-{}".format(sts_client.get_caller_identity()['Account']))
        s3_client.create_bucket(Bucket=bucket_name, ACL='private')
	s3_client.put_public_access_block( Bucket=bucket_name, \ 
                                           PublicAccessBlockConfiguration={ "BlockPublicAcls": True, \
                                                                            "BlockPublicPolicy": True, \
                                                                            "IgnorePublicAcls" : True, \
                                                                            "RestrictPublicBuckets" : True } )
        return bucket_name
    else:
        print("{}-1 already exists.".format(bucket_name))
        return bucket_name


def transform_certificate(certificate):
    lines = re.split('\n', certificate)
    return "{}{}".format('\\n\\\n'.join([ i.strip() for i in lines[1:-2] ]), '\\n\\')


def generate_aws_iot_certs(certificates):
    print("Certificates: {}".format(certificates))
    # Use current directory for templates
    file_loader = FileSystemLoader('.')
    # load environment
    e = Environment(loader=file_loader)
    # Load template and render
    cert = transform_certificate(certificates['certificatePem'])
    private_cert = transform_certificate(certificates['keyPair']['PrivateKey'])
    template = e.get_template('aws_iot_certificates.template')
    return template.render(cert=cert, private_cert=private_cert).encode('utf-8')


def attach_certificate(client, thing, certificates):
    client.attach_thing_principal(thingName=thing['thingName'], principal=certificates['certificateArn'])


def generate_iot_code(client):
    file_loader = FileSystemLoader('.')
    e = Environment(loader=file_loader)
    aws_endpoint_host = client.describe_endpoint(endpointType='iot:Data')['endpointAddress']
    template = e.get_template('TempGatherPlusIoT.template')
    return template.render(wifi_ssid=wifi_ssid, wifi_password=wifi_password, aws_endpoint_host=aws_endpoint_host).encode('utf-8')


def upload_object_s3(client, bucket, obj, filename):
    print("bucket: {}".format(bucket))
    return client.put_object(Bucket=bucket, Body=obj.encode('utf-8'), Key=filename)


def main():
    thing_type = create_ESP32_thing_type(client=boto3.client('iot', config=config))
    thing_group = create_IoT_TemperatureSensors_group(client=boto3.client('iot', config=config))
    thing = create_IoT_thing(client=boto3.client('iot', config=config))

    try:
        add_thing_to_group(client=boto3.client('iot', config=config), thing=thing, thing_group=thing_group)
    except KeyError:
        print("Retrying, thing_group may not yet have been replicated fully.")
        add_thing_to_group(client=boto3.client('iot', config=config), thing=thing, thing_group=thing_group)

    create_policy(client=boto3.client('iot', config=config), thing_group=thing_group)
    
    bucket = create_iot_code_bucket(s3_client=boto3.client('s3', config=config), sts_client=boto3.client('sts', config=config))
    certificates = create_certificates(client=boto3.client('iot', config=config))
    attach_certificate(client=boto3.client('iot', config=config), thing=thing, certificates=certificates)
    upload_object_s3(   client=boto3.client('s3'), \
                        bucket=bucket,\
                        obj=generate_aws_iot_certs( certificates ) ,\
                        filename='aws_iot_certificates.c')
    upload_object_s3(   client=boto3.client('s3'), \
                        bucket=bucket,\
                        obj=generate_iot_code(client=boto3.client('iot', config=config)),\
                        filename='TempGatherPlusIoT.ino')


if __name__ == '__main__':
    main()
