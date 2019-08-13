import boto3
import pytest
import uuid
import json
from unittest.mock import patch
from moto import mock_acm, mock_lambda
from issued_certificate_provider import handler, provider as issued_certificate_provider
from fixtures import certificate, issued_certificate
from moto.acm.models import AWSError
from moto.acm.responses import AWSCertificateManagerResponse

def describe_certificate(self):
    arn = self._get_param('CertificateArn')

    if arn is None:
        msg = 'A required parameter for the specified action is not supplied'
        return json.dumps({'__type': 'MissingParameter', 'message': msg}), dict(status=400)
    
    return self.acm_backend.get_certificate(arn)

def describe_certificate_dns(self):
    try:
        cert_bundle = describe_certificate(self)
    except AWSError as err:
        return err.response()
    
    result = cert_bundle.describe()
    result['Certificate']['DomainValidationOptions'] = []

    for name in result['Certificate']['SubjectAlternativeNames'] + [ result['Certificate']['DomainName'] ]:
        result['Certificate']['DomainValidationOptions'].append(
            {
                'DomainName': name,
                'ValidationDomain': name,
                'ValidationMethod': 'DNS',
                'ValidationStatus': 'SUCCESS',
                'ResourceRecord': {
                    'Name': '_x9.host.subdomain.'+name,
                    'Type': 'CNAME',
                    'Value': '_x10.acm-validation.aws'
                }
            }
        )

    return json.dumps(result)

class Counter(object):
    def __init__(self):
        self.count = 0

    def increment(self, *args, **kwargs):
        self.count += 1

@mock_acm
def test_attempt_increment():
    issued_certificate_provider.set_request(
        Request("Create", "dfsdfsdfsfdfsdfsdfs"), {}
    )
    assert issued_certificate_provider.attempt == 1
    issued_certificate_provider.increment_attempt()
    assert issued_certificate_provider.attempt == 2

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_await_pending_completion():
    counter = Counter()
    cert = certificate()
    issued_certificate_provider.invoke_lambda = counter.increment

    request = Request("Create", cert["CertificateArn"])
    response = handler(request, ())
    assert issued_certificate_provider.asynchronous
    assert counter.count == 1

    request = Request("Update", cert["CertificateArn"])
    response = handler(request, ())
    assert issued_certificate_provider.asynchronous
    assert counter.count == 2

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_await_completion_issued():
    cert = certificate()
    arn = cert["CertificateArn"]

    acm = boto3.client("acm")
    cert = acm.get_certificate(CertificateArn=arn)
    cert['status'] = "ISSUED"
    
    counter = Counter()

    issued_certificate_provider.async_reinvoke = counter.increment

    request = Request("Create", arn)
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert not issued_certificate_provider.asynchronous


class Request(dict):
    def __init__(self, request_type, certificate_arn, physical_resource_id=None):
        request_id = "request-%s" % uuid.uuid4()
        self.update(
            {
                "RequestType": request_type,
                "ResponseURL": "https://httpbin.org/put",
                "StackId": "arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid",
                "RequestId": request_id,
                "ResourceType": "Custom::IssuedCertificate",
                "LogicalResourceId": "Record",
                "ResourceProperties": {"CertificateArn": certificate_arn},
            }
        )

        if physical_resource_id:
            self["PhysicalResourceId"] = physical_resource_id
