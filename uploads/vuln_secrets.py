import boto3

def connect_aws():
    # Danger: Hardcoded AWS Credentials (B108)
    aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'
    aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    
    # Danger: Hardcoded Password (B105)
    db_password = 'super_secret_password_123'
    
    print('Connecting...')
    return True
