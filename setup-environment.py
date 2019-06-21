#!/usr/bin/env python

import boto3
import re
import sys
from jinja2 import Environment, FileSystemLoader


wifi_ssid = 'foo'
wifi_password = '12345'


def create_ESP32_thing_type(client):
    if 'ESP32-Things' not in [ i['thingTypeName'] for i in client.list_thing_types()['thingTypes'] ]:
        return client.create_thing_type(thingTypeName='ESP32-Things',tags=[{'Key': 'Purpose', 'Value' : 'Demo'}])


def create_IoT_TemperatureSensors_group(client):
    if 'TemperatureSensors' not in [ i['groupName'] for i in client.list_thing_groups()['thingGroups'] ]:
        return client.create_thing_group(  thingGroupName='TemperatureSensors', \
                                    thingGroupProperties={  'thingGroupDescription' : '', \
                                                            'attributePayload' : { 'attributes' : { 'Core' : 'ESP32', 'Sensor' : 'DHT22'} }})


def create_IoT_thing(client):
    if 'IoT-Temperature-Device' not in [ i['thingName'] for i in client.list_things()['things'] ]:
        return client.create_thing(thingName='IoT-Temperature-Device',thingTypeName='ESP32-Things')


def add_thing_to_group(client, thing, thing_group):
    client.add_thing_to_group(  thingGroupName=thing_group['thingGroupName'],    \
                                thingGroupArn=thing_group['thingGroupArn'],
                                thingName=thing['thingName'],
                                thingArn=thing['thingArn'] )


def create_policy(client):
    if 'TemperatureSensorPolicy' not in [ i['policyName'] for i in client.list_policies()['policies'] ]:
        return client.create_policy(    policyName='TemperatureSensorPolicy',\
                                        policyDocument='{   "Version" : "2012-10-17",\
                                                            "Statement":\
                                                                [ { "Effect" : "Allow",\
                                                                    "Action" : "iot:*",\
                                                                    "Resource" : "*"} ]}'   )


def attach_policy(client, policy, thing_group):
    client.attach_policy(policyName=policy['policyName'], target=thing_group['thingGroupArn'])


def create_certificates(client):
    return client.create_keys_and_certificates(setAsActive=True)

    
def create_iot_code_bucket(s3_client, sts_client):
    if "iot-code-{}".format(sts_client.get_caller_identity()['Account']) not in [ i['Name'] for i in sts_client.list_buckets()['Buckets']]:
        return s3_client.create_bucket(Bucket="iot-code-{}".format(sts_client.get_caller_identity()['Account']))


def transform_certificate(certificate):
    lines = re.split('\n', certificate)
    return "{}{}".format('\\n\\\n'.join([ i.strip() for i in lines[1:-2] ]), '\\n\\')


def generate_aws_iot_certs(certificates):
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
    return client.put_object(Bucket=bucket['Name'], Body=obj.encode('utf-8'), Key=filename)


def main():
    thing_type = create_ESP32_thing_type(client=boto3.client('iot'))
    thing_group = create_IoT_TemperatureSensors_group(client=boto3.client('iot'))
    thing = create_IoT_thing(client=boto3.client('iot'))
    add_thing_to_group(client=boto3.client('iot'), thing=thing, thing_group=thing_group)
    policy = create_policy(client=boto3.client('iot'))
    attach_policy(client=boto3.client('iot'), policy=policy, thing_group=thing_group)
    bucket = create_iot_code_bucket(s3_client=boto3.client('s3'), sts_client=boto3.client('sts'))
    certificates = create_certificates(client=boto3.client('iot'))
    attach_certificate(client=boto3.client('iot'), thing=thing, certificates=certificates)
    upload_object_s3(   client=boto3.client('s3'), \
                        bucket=bucket,\
                        obj=generate_aws_iot_certs( certificates ) ,\
                        filename='aws_iot_certificates.c')
    upload_object_s3(   client=boto3.client('s3'), \
                        bucket=bucket,\
                        obj=generate_iot_code(client=boto3.client('iot')),\
                        filename='TempGatherPlusIoT.ino')


if __name__ == '__main__':
    main()
