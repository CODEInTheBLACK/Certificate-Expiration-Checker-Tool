import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

def get_certificate_from_host(hostname: str, port: int = 443) -> x509.Certificate:
    """Fetch the TLS certificate from a given hostname."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return cert

def certificate_details(cert: x509.Certificate):
    """Extract and return details from the TLS certificate."""
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

def display_certificate_info(details: dict):
    """Display certificate details in a message box."""
    info = "\n".join(f"{key}: {value}" for key, value in details.items())
    messagebox.showinfo("Certificate Details", info)

def fetch_and_display_certificate():
    """Fetch the certificate from the hostname and display details."""
    hostname = entry.get()
    try:
        cert = get_certificate_from_host(hostname)
        details = certificate_details(cert)
        display_certificate_info(details)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve certificate: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("SSL Certificate Checker")

# Dark mode colors
bg_color = "#1e1e1e"  # Dark background
fg_color = "#00ff00"  # Cyber green text
entry_bg_color = "#333333"  # Slightly lighter background for entry

# Configure root window background
root.configure(bg=bg_color)

# Frame setup
frame = tk.Frame(root, padx=10, pady=10, bg=bg_color)
frame.pack(padx=10, pady=10)

# Label setup
label = tk.Label(frame, text="Enter the hostname to check:", bg=bg_color, fg=fg_color)
label.grid(row=0, column=0, padx=5, pady=5)

# Entry setup
entry = tk.Entry(frame, width=40, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
entry.grid(row=0, column=1, padx=5, pady=5)

# Button setup
button = tk.Button(frame, text="Check Certificate", command=fetch_and_display_certificate, bg=bg_color, fg=fg_color)
button.grid(row=1, column=0, columnspan=2, pady=10)

# Customize messagebox color (unfortunately, tkinter does not allow for easy customization of messagebox)
# The messagebox will appear in the system default theme.

root.mainloop()
