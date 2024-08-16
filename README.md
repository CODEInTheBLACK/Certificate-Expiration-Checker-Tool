# This script was inspired by the "Programming with AI - Mini Course" by Heath Adams
Link to course provider: https://academy.tcm-sec.com/courses/

---

## Prompt I gave to ChatGPT:

I need a Python script that scrapes websites only for TLS certificates. The script should include the following features:

Common Name: Issued To
Common Name: Issued By
Validity Period: Dates
Validity: Days to expiration
Certificate Expired: Yes or No
Details Tab: All Information
The script should use the cryptography library for handling certificates and keys. Provide code that demonstrates each of these features in a modular fashion. Include comments explaining each part of the code and any necessary dependencies.

---

## Command:
python3 IsYourCertInTheBlack.py

You will be prompted to provide a hostname (Domain Name)
Hostname used for below output: feistyduck.com

## Output:
Certificate Details:
Issued To: blog.ivanristic.com
Issued By: R10
Validity Period: From: 2024-06-21 23:09:47, To: 2024-09-19 23:09:46
Days to Expiration: 34
Certificate Expired: No

## Dependencies:
You need the following Python libraries:

cryptography
requests (if you choose to fetch data from other URLs or APIs)
To install them, you can use:

pip install cryptography requests
