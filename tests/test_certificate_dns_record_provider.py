import uuid
import responses
import json
import moto
from unittest.mock import patch
from moto import mock_acm, mock_lambda
from moto.acm.models import AWSError
from moto.acm.responses import AWSCertificateManagerResponse
from provider import handler
from fixtures import certificate, email_certificate

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

def describe_certificate_email(self):
    try:
        cert_bundle = describe_certificate(self)
    except AWSError as err:
        return err.response()

    result = cert_bundle.describe()
    result['Certificate']['DomainValidationOptions'] = [
        {
            'DomainName': result['Certificate']['DomainName'],
            'ValidationMethod': 'EMAIL',
            'ValidationEmails': [
                'john.doe@example.com'
            ]
        }
    ]

    return json.dumps(result)
    

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_retrieval_of_dns_record():
    responses.add_passthru("https://")
    cert = certificate()

    request = Request("Create", cert["CertificateArn"])
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert "Name" in response["Data"]
    assert "Type" in response["Data"]
    assert "Value" in response["Data"]
    assert response["Data"]["Type"] == "CNAME"
    assert "PhysicalResourceId" in response
    record_name = response["Data"]["Name"]
    physical_resource_id = response["PhysicalResourceId"]
    assert physical_resource_id == record_name

    request = Request(
        "Create",
        cert["CertificateArn"],
        cert["SubjectAlternativeNames"][1],
    )
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert "Name" in response["Data"]
    assert "Type" in response["Data"]
    assert "Value" in response["Data"]
    assert response["Data"]["Type"] == "CNAME"
    assert "PhysicalResourceId" in response

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_retrieval_of_dns_record_via_update():
    responses.add_passthru("https://")
    cert = certificate()

    request = Request("Update", cert["CertificateArn"])
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert "Name" in response["Data"]
    assert "Type" in response["Data"]
    assert "Value" in response["Data"]
    assert response["Data"]["Type"] == "CNAME"
    assert "PhysicalResourceId" in response
    assert response["PhysicalResourceId"] == response["Data"]["Name"]

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_retrieval_of_non_existing_domain_name():
    responses.add_passthru("https://")
    cert = certificate()

    request = Request("Update", cert["CertificateArn"])
    request["ResourceProperties"]["DomainName"] = "nonexisting.domain.name"
    response = handler(request, {})
    assert response["Status"] == "FAILED", response["Reason"]
    assert response["Reason"].startswith("No validation option found for domain")

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_dns)
def test_retrieval_non_existing_certificate():
    responses.add_passthru("https://")

    request = Request(
        "Create",
        "arn:aws:acm:eu-central-1:111111111111:certificate/ffffffff-ffff-ffff-ffff-ffffffffffff",
    )
    response = handler(request, {})
    assert response["Status"] == "FAILED", response["Reason"]
    assert "ResourceNotFoundException" in response["Reason"]

@mock_acm
@mock_lambda
@patch.object(AWSCertificateManagerResponse, 'describe_certificate', describe_certificate_email)
def test_create_incorrect_validation_method():
    cert = email_certificate()

    request = Request("Create", cert["CertificateArn"])
    response = handler(request, {})
    assert response["Status"] == "FAILED", response["Reason"]
    assert response["Reason"].startswith("domain is using validation method")


class Request(dict):
    def __init__(
        self, request_type, certificate_arn, domain_name=None, physical_resource_id=None
    ):
        request_id = "request-%s" % uuid.uuid4()
        self.update(
            {
                "RequestType": request_type,
                "ResponseURL": "https://httpbin.org/put",
                "StackId": "arn:aws:cloudformation:us-east-1:EXAMPLE/stack-name/guid",
                "RequestId": request_id,
                "ResourceType": "Custom::CertificateDNSRecord",
                "LogicalResourceId": "Record",
                "ResourceProperties": {"CertificateArn": certificate_arn},
            }
        )

        if domain_name:
            self["ResourceProperties"]["DomainName"] = domain_name

        if physical_resource_id:
            self["PhysicalResourceId"] = physical_resource_id
