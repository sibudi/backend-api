import helper
import json
import logging
import minirouter
import requests
from requests.auth import HTTPBasicAuth


logger = {}
fdc_config_v35 = {}
kms_config = {}
@minirouter.route(methods=['GET'], content_type='text/plain', path=['/v1/inquiry'])
def inquiry():
    query_string = minirouter.router.getQueryString()
    context = minirouter.router.getContext()
    fdc_config = fdc_config_v35

    url = fdc_config['url']
    password = helper.decrypt_string(context, fdc_config['password'])
    params = {
        'id' : query_string['id'],
        'reason' : query_string['reason'],
        'reffid' : query_string['reffid'] 
    }
    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(fdc_config['username'], password)
    resp = requests.get(url, params, headers=headers, auth=auth)
    return minirouter.return_200(resp.text)


@minirouter.route(methods=['GET'], content_type='text/plain', path=['/v1/UserPassword'])
def UserPassword():
    query_string = minirouter.router.getQueryString()
    context = minirouter.router.getContext()
    fdc_config = fdc_config_v35

    url = fdc_config['url_UserPassword']
    password_baru = query_string.get('password', '')
    payload = "{\"Password\": \"" + password_baru + "\"}"
    password = helper.decrypt_string(context, fdc_config['password'])
    
    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(fdc_config['username'], password)
    resp = requests.post(url, headers=headers, auth=auth, data = payload)

    # also change the password in tablestore
    if(password_baru != ''):
        encrypted_string = helper.encrypt_string(context, kms_config['key_id'], password_baru)

        primary_key = [('group', 'url_auth_v35')]
        upsert_columns = [('password', encrypted_string)]
        code, error_message = helper.upsert(context, primary_key, upsert_columns)
        if code != -1:
            logger.info("SUCCESS - Upsert")
        else:
            logger.error(f"FAILED - {error_message}")

    return minirouter.return_200(resp.text)


"""not implemented yet, zip password located at different tablestore"""
@minirouter.route(methods=['GET'], content_type='text/plain', path=['/v1/ZipPassword'])
def ZipPassword():
    query_string = minirouter.router.getQueryString()
    context = minirouter.router.getContext()
    fdc_config = fdc_config_v1 if query_string.get('v', 0) == '1' else fdc_config_v35

    url = "http://149.129.234.48/api/ZipPassword" #fdc_config['url']
    payload = "{\"zipPwd\": \"HbWSJjvMY7#2\"}"
    password = helper.decrypt_string(context, fdc_config['password'])

    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(fdc_config['username'], password)
    resp = requests.post(url, headers=headers, auth=auth, data = payload)
    return minirouter.return_200(resp.text)


def update_row(context, group_code):
    import os
    
    creds = context.credentials
    client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
        creds.accessKeyId, creds.accessKeySecret,
        os.environ['TABLE_STORE_INSTANCE_NAME'],
        sts_token=creds.securityToken)
    primary_key = [('group', group_code)]
    
    update_of_attribute_columns = {
        'PUT' : [('teskol', 2)]
    }
    row = Row(primary_key, update_of_attribute_columns)
    condition = Condition(RowExistenceExpectation.IGNORE, SingleColumnCondition("teskol", 1, ComparatorType.EQUAL)) # update row only when this row is exist
    consumed, return_row = client.update_row(group_code, row, condition)
    logger.info('Update succeed, consume %s write cu.' % consumed.write)


######################################################################
########################## HANDLER FUNCTION ##########################
######################################################################
def init(context):
  try:
    global logger
    global kms_config
    logger = logging.getLogger()
    minirouter.router.initialize(ROUTER_FILE_NAME=__name__, ROUTER_AUDIENCE='')#jwt_config["audience"])
    
    kms_config = helper.get_configuration(context, 'kms')
  
  except Exception as ex:
    logger.error(ex)
    raise Exception("Internal Server Error - Failed when initializing")
  
  return ""


def handler(event, context):
    global fdc_config_v35
    fdc_config_v35 = helper.get_configuration(context, 'url_auth_v35')
      
    try:
        return minirouter.router.routeRequest(event, context)
    except minirouter.base_router.RouteException as rex:
        logger.error(rex)
        if (rex.code == "400"):
            return minirouter.return_400(rex.message)
        else:
            return minirouter.return_500(rex.message)
    except Exception as error:
        import traceback
        logger.error(error)
        logger.error(traceback.format_exc())
        return minirouter.return_500(error)
