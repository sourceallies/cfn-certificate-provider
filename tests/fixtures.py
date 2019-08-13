import boto3
import pytest
import uuid

acm = boto3.client("acm")


def certificate():
    name = "test-%s.binx.io" % uuid.uuid4()
    alt_name = "test-%s.binx.io" % uuid.uuid4()
    certificate = acm.request_certificate(
        DomainName=name, ValidationMethod="DNS", SubjectAlternativeNames=[alt_name]
    )
    return acm.describe_certificate(CertificateArn=certificate["CertificateArn"])[
        "Certificate"
    ]

def issued_certificate():
    acm.get_paginator("list_certificates")
    result = None
    for response in acm.get_paginator("list_certificates").paginate():
        for certificate in map(
            lambda c: acm.describe_certificate(CertificateArn=c["CertificateArn"]),
            response["CertificateSummaryList"],
        ):
            if certificate["Certificate"]["Status"] == "ISSUED":
                result = certificate["Certificate"]
                break

    return result

def email_certificate():
    name = "test-%s.binx.io" % uuid.uuid4()
    alt_name = "test-%s.binx.io" % uuid.uuid4()
    certificate = acm.request_certificate(
        DomainName=name, ValidationMethod="EMAIL", SubjectAlternativeNames=[alt_name]
    )
    return acm.describe_certificate(CertificateArn=certificate["CertificateArn"])[
        "Certificate"
    ]
