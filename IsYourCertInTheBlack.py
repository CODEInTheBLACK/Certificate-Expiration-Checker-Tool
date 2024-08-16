# Brought to you by "CODE In The Black!"
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def get_certificate_from_host(hostname: str, port: int = 443) -> x509.Certificate:
    """Fetch the TLS certificate from a given hostname."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return cert

def certificate_details(cert: x509.Certificate):
    """Extract and print details from the TLS certificate."""
    # Extract common names
    common_name_issued_to = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    common_name_issued_by = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    
    # Validity Period
    validity_period = f"From: {cert.not_valid_before}, To: {cert.not_valid_after}"
    
    # Days to Expiration
    days_to_expiration = (cert.not_valid_after - datetime.utcnow()).days
    
    # Certificate Expired
    cert_expired = "Yes" if days_to_expiration < 0 else "No"
    
    # Detailed Information
    details = {
        "Issued To": common_name_issued_to,
        "Issued By": common_name_issued_by,
        "Validity Period": validity_period,
        "Days to Expiration": days_to_expiration,
        "Certificate Expired": cert_expired
    }
    
    return details

def print_certificate_info(details: dict):
    """Print certificate details."""
    print("Certificate Details:")
    for key, value in details.items():
        print(f"{key}: {value}")

def main():
    hostname = input("Enter the hostname to check: ")
    cert = get_certificate_from_host(hostname)
    details = certificate_details(cert)
    print_certificate_info(details)

if __name__ == "__main__":
    main()


