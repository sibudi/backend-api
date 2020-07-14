import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, 'src/')
import minirouter
import requests
from urllib.parse import unquote
from requests.auth import HTTPBasicAuth


def inquiry_local(url, params):
    query_string = {}
    for param in params:
        temp = param.split("=")
        query_string[temp[0]] = unquote(temp[1])

    ''' # ganti pake ini kalau mau dipindah ke function compute (index.py)
    params = {
        'id' : query_string['id'],
        'reason' : query_string['reason'],
        'reffid' : query_string['reffid'] 
    }
    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(username, password)
    resp = requests.get(url, params, headers=headers, auth=auth)
    '''
    params = {
        'v' : query_string['v'],
        'id' : query_string['id'],
        'reason' : query_string['reason'],
        'reffid' : query_string['reffid'] 
    }
    headers = {'Content-Type': 'text/plain', 'Authorization': 'APPCODE 8e1dd29b33e344719adcd04176cbd7c9'}
    resp = requests.get(url, params, headers=headers)
    return minirouter.return_200(resp.text)


def userPassword_local(url):
    headers = {'Content-Type': 'text/plain', 'Authorization': 'APPCODE 8e1dd29b33e344719adcd04176cbd7c9'}
    resp = requests.get(url, headers=headers)
    return minirouter.return_200(resp.text)


def zipPassword_local(url):
    headers = {'Content-Type': 'text/plain', 'Authorization': 'APPCODE 8e1dd29b33e344719adcd04176cbd7c9'}
    resp = requests.get(url, headers=headers)
    return minirouter.return_200(resp.text)


def main():
    url_inquiry = 'http://40074a4e6d57440483eb01cd049fa259-ap-southeast-5.alicloudapi.com/v1/inquiry?'
    params = 'v=1&id=3207025501730003&reason=1&reffid=123' # hapus v=1& kalau mau pindah ke function compute
    
    # inquiry
    #print(inquiry_local(url_inquiry, params.split("&")))

    # UserPassword
    url_userPassword = 'http://40074a4e6d57440483eb01cd049fa259-ap-southeast-5.alicloudapi.com/v1/UserPassword'
    #userPassword_local(url_userPassword)

    # ZipPassword
    url_zipPassword = 'http://40074a4e6d57440483eb01cd049fa259-ap-southeast-5.alicloudapi.com/v1/ZipPassword'
    zipPassword_local(url_zipPassword)

    
if __name__ == '__main__':
    main()