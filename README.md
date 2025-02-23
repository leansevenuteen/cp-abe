# cp-abe
Ciphertext-Policy Attribute-Based Encryption using the BSW07 and SP21 schemes

## Introduction
Ciphertext-Policy Attribute-Based Encryption (CP-ABE) is a sophisticated encryption method that enables data access based on user attributes. The ciphertext is embedded with a special policy, allowing only users with attributes that match the policy to decrypt it. This approach enhances flexibility and fine-grained access control, particularly in environments like cloud storage where data might need to be shared selectively.

This project is applied in the real estate field, utilizing two CP-ABE schemas, SP21 and BSW07, for policy encryption. The relevant external parties include customers, government employees, banks, and company employees. Currently, the project has achieved confidentiality in terms of security goals but lacks authentication and authorization mechanisms.

## Deployment Architecture
### Overview

<p align="center">
  <img src="https://github.com/user-attachments/assets/44edea67-556f-4796-9f63-65e10a1e545c" alt="Overview" width="750px">
</p>

### System Workflow
- Phase 1: System Initialization
The system generates a Global Public Key (PK) and a Master Key (MK). The PK is used for encryption, and the MK is used for decryption, together creating a Secret Key (SK) for data decryption.

- Phase 2: Secret Key Generation
The algorithm takes the PK, MK, and user attribute set (S) as input, with the access policy (A) expressed as a Boolean. The system returns a Secret Key (SK) derived from the user’s attributes for decrypting ciphertext.

- Phase 3: Data Encryption by Owners
The encryption algorithm uses PK, data (M), access policy (A), and a key pair (P1 and P2) as input, producing a ciphertext (CT) that only users with attributes satisfying the access policy can decrypt. The policy is encrypted using AES-GCM-256 to mitigate risks associated with storing raw text.

- Phase 4: Data Decryption by Users
The decryption algorithm takes MK, ciphertext (CT), SK, and the key pair (P1 and P2) as input. It decrypts the policy and checks if the SK aligns with the access policy. If the attributes satisfy the policy A, the SK decrypts the plaintext as M.

## Usage
Make sure you have installed the Charm Crypto Framework before cloning this project. Since the installation of Charm Crypto is complex and time-consuming, we will provide the relevant documentation [here](https://github.com/JHUISI/charm).

Run the following code to start our project:
```python
python CP-ABE/program.py
```

Considering the `CP-ABE/QueryDB.py` script to change our database to yours. In addition, the current source code is running the BSW07 schema. If you wish to use a different schema that is more suitable, you can consider the schemas provided by Charm Crypto [here](https://jhuisi.github.io/charm/py-modindex.html) and modify the code in the `CP-ABE/program.py` script accordingly.
