import boto3
import pytest
import uuid
import json
from unittest.mock import patch
from botocore.exceptions import ClientError
from moto import mock_acm, mock_lambda
from moto.acm.responses import AWSCertificateManagerResponse
from certificate_provider import handler

acm = boto3.client("acm")

def update_certificate_options(any):
    return json.dumps({'__type':'InvalidStateException'}), dict(status=400)

@mock_acm
def test_create_wildcard():
    name = "test-%s.binx.io" % uuid.uuid4()

    request = Request("Create", f'*.{name}')
    request["ResourceProperties"]["DomainValidationOptions"] = [
      { 'DomainName': f'*.{name}', 'ValidationDomain': name }
    ]
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]
    physical_resource_id = response["PhysicalResourceId"]

@mock_acm
@patch.object(AWSCertificateManagerResponse, 'update_certificate_options', update_certificate_options, create=True)
def test_create():
    name = "test-%s.binx.io" % uuid.uuid4()
    new_name = "test-new-%s.binx.io" % uuid.uuid4()
    alt_name = "test-%s.binx.io" % uuid.uuid4()

    request = Request("Create", name)
    request["ResourceProperties"]["SubjectAlternativeNames"] = [alt_name]
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]
    physical_resource_id = response["PhysicalResourceId"]

    request["RequestType"] = "Update"
    request["PhysicalResourceId"] = physical_resource_id
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response["Reason"] == "nothing to change"
    assert physical_resource_id == response["PhysicalResourceId"]

    request["OldResourceProperties"] = request["ResourceProperties"].copy()
    request["ResourceProperties"]["DomainName"] = new_name
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]

    request["OldResourceProperties"] = request["ResourceProperties"].copy()
    request["ResourceProperties"]["SubjectAlternativeNames"] = ["new-" + alt_name]
    response = handler(request, ())
    assert response["Status"] == "FAILED", response["Reason"]
    assert response["Reason"].startswith(
        'You can only change the "Options" and "DomainName" of a certificate,'
    ), response["Reason"]

    request["ResourceProperties"]["SubjectAlternativeNames"] = [alt_name]
    request["ResourceProperties"]["Options"] = {
        "CertificateTransparencyLoggingPreference": "DISABLED"
    }
    response = handler(request, ())
    assert response["Status"] == "FAILED", response["Reason"]
    assert response["Reason"].startswith(
        "An error occurred (InvalidStateException) when calling the UpdateCertificateOptions operation"
    )

    request["RequestType"] = "Delete"
    response = handler(request, ())
    assert response["Status"] == "SUCCESS", response["Reason"]
    try:
        acm.delete_certificate(CertificateArn=physical_resource_id)
        assert False, "Delete operation failed for {}".format(physical_resource_id)
    except acm.exceptions.ResourceNotFoundException:
        pass


class Request(dict):
    def __init__(self, request_type, domain_name, physical_resource_id=None):
        request_id = "request-%s" % uuid.uuid4()
        self.update(
            {
                "RequestType": request_type,
                "ResponseURL": "https://httpbin.org/put",
                "StackId": "arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid",
                "RequestId": request_id,
                "ResourceType": "Custom::Certificate",
                "LogicalResourceId": "Record",
                "ResourceProperties": {
                    "DomainName": domain_name,
                    "ValidationMethod": "DNS",
                },
            }
        )

        if physical_resource_id:
            self["PhysicalResourceId"] = physical_resource_id
