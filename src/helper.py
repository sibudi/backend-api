SQL_CONNECTION = {}
INTERNAL_BUCKET = {}
PUBLIC_BUCKET = {}
NOTIFICATION_CONFIG = {}
ORIGIN = ""

def connect_to_mysql(context, mysql_config):
 import minipymysql as pymysql
 return pymysql.connect(
  host=mysql_config['host'],
  port=3306,
  user=mysql_config['username'],
  password=decrypt_string(context, mysql_config['password']),
  db=mysql_config['db'],
  charset='utf8mb4',
  cursorclass=pymysql.cursors.DictCursor)

def insert(context, primary_key, columns):
  import os
  from tablestore import OTSClient, Row, Condition, RowExistenceExpectation, OTSClientError, OTSServiceError
  try:
    creds = context.credentials
    client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
      creds.accessKeyId, creds.accessKeySecret,
      os.environ['TABLE_STORE_INSTANCE_NAME'],
      sts_token=creds.securityToken)
    row = Row(primary_key, columns)
    client.put_row(os.environ['TABLE_STORE_TABLE_NAME'], row, Condition(RowExistenceExpectation.EXPECT_NOT_EXIST))
    return (0, '')
  except OTSClientError as e:
    raise e
  except OTSServiceError as e:
    if e.get_error_code() == 'OTSConditionCheckFail':
      return (-1, f"Duplicate row {primary_key}")
    else:
      raise e

def upsert(context, primary_key, columns):
  import os
  from tablestore import OTSClient, Row, Condition, RowExistenceExpectation, OTSClientError, OTSServiceError
  try:
    creds = context.credentials
    client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
      creds.accessKeyId, creds.accessKeySecret,
      os.environ['TABLE_STORE_INSTANCE_NAME'],
      sts_token=creds.securityToken)
    update_of_attribute_columns = {
        'PUT' : columns,
    }
    row = Row(primary_key, update_of_attribute_columns)
    client.update_row(os.environ['TABLE_STORE_TABLE_NAME'], row, Condition(RowExistenceExpectation.IGNORE))
    
    return (0, '')
  except OTSClientError as e:
    raise e
  except OTSServiceError as e:
    raise e

def delete(context, primary_key):
  import os
  from tablestore import OTSClient, Row, Condition, RowExistenceExpectation, OTSClientError, OTSServiceError
  try:
    creds = context.credentials
    client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
      creds.accessKeyId, creds.accessKeySecret,
      os.environ['TABLE_STORE_INSTANCE_NAME'],
      sts_token=creds.securityToken)
    row = Row(primary_key)
    client.delete_row(os.environ['TABLE_STORE_TABLE_NAME'], row, Condition(RowExistenceExpectation.EXPECT_EXIST))
    return (0, '')
  except OTSClientError as e:
    raise e
  except OTSServiceError as e:
    if e.get_error_code() == 'OTSConditionCheckFail':
      return (-1, f"Row not exist {primary_key}")
    else:
      raise e

def select(context, primary_key, columns_to_get=[], column_filter=None):
  import os
  from tablestore import OTSClient, OTSClientError, OTSServiceError
  try:
    creds = context.credentials
    client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
     creds.accessKeyId, creds.accessKeySecret,
     os.environ['TABLE_STORE_INSTANCE_NAME'],
     sts_token=creds.securityToken)
    max_version = 1
    consumed, return_row, next_token = client.get_row(
      os.environ['TABLE_STORE_TABLE_NAME'],
      primary_key,
      columns_to_get, column_filter, max_version)
    json = {}
    if return_row is None:
      return (-1, f"Row not found {primary_key}")
    
    for att in return_row.attribute_columns:
      json[att[0]] = att[1]
    return(0,json)
  except OTSClientError as e:
    raise e
  except OTSServiceError as e:
    raise e
  
def get_configuration(context, group_code):
 import os
 from tablestore import OTSClient
 creds = context.credentials
 client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
  creds.accessKeyId, creds.accessKeySecret,
  os.environ['TABLE_STORE_INSTANCE_NAME'],
  sts_token=creds.securityToken)
 primary_key = [('group', group_code)]
 columns_to_get = []
 consumed, return_row, next_token = client.get_row(
  os.environ['TABLE_STORE_TABLE_NAME'],
  primary_key,
  columns_to_get, None, 1)
 json = {}
 for att in return_row.attribute_columns:
  json[att[0]] = att[1]
 return json

def decrypt_string(context, encrypted_string):
 import json
 from aliyunsdkcore.auth import credentials
 from aliyunsdkcore.client import AcsClient  
 from aliyunsdkkms.request.v20160120.DecryptRequest import DecryptRequest
 creds = context.credentials
 sts_credentials = credentials.StsTokenCredential(creds.accessKeyId, creds.accessKeySecret, creds.securityToken) 
 client = AcsClient(region_id = 'ap-southeast-5',credential = sts_credentials)
 request = DecryptRequest()
 request.set_CiphertextBlob(encrypted_string)
 response = str(client.do_action_with_exception(request), encoding='utf-8')
 return json.loads(response)['Plaintext']

def encrypt_string(context, key_id, plain_text):
  import json
  from aliyunsdkcore.auth import credentials
  from aliyunsdkcore.client import AcsClient  
  from aliyunsdkkms.request.v20160120.EncryptRequest import EncryptRequest
  creds = context.credentials
  sts_credentials = credentials.StsTokenCredential(creds.accessKeyId, creds.accessKeySecret, creds.securityToken) 
  client = AcsClient(region_id = 'ap-southeast-5',credential = sts_credentials)
  request = EncryptRequest()
  request.set_KeyId(key_id)
  request.set_Plaintext(plain_text)
  response = str(client.do_action_with_exception(request), encoding='utf-8')
  return json.loads(response)['CiphertextBlob']

def is_json(myjson):
  import json
  try:
    json_object = json.loads(myjson)
  except ValueError as e:
    return False
  return True

def signOssObject(http_method, file_name, expiration_time, headers=None, public_access=True):
  import json
  bucket = PUBLIC_BUCKET

  signed_url = f"{bucket.sign_url(http_method, file_name, expiration_time, headers)}"
  return signed_url

#######################################################################
########################### HELPER FUNCTION ###########################
#######################################################################
def send_email(subject, message, to, cc=None, bcc=None, attachments=None):
  import requests
  import json
  data = {
    "subject": subject,
    "message": message,
    "to": to,
    "cc": cc if cc is not None else "",
    "bcc": bcc if bcc is not None else "",
    "attachments": attachments if attachments is not None else []
  }
  
  token = NOTIFICATION_CONFIG['x-authorization-token']
  endpoint = NOTIFICATION_CONFIG['endpoint']
  headers = {'Content-Type': 'application/json', 'x-authorization-token': token, 'Origin':f"{NOTIFICATION_CONFIG['endpoint'].replace('notificationapi', ORIGIN)}"}
  resp = requests.post(f"{endpoint}/email",
      data=json.dumps(data), headers=headers)
