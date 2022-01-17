import os
import json
import requests
from dateutil import tz,parser
import datetime
from msrestazure.azure_active_directory import MSIAuthentication, ServicePrincipalCredentials
from azure.keyvault import KeyVaultClient


#Authenticate function with key vault
def get_key_vault_credentials():
    """This tries to get a token using MSI, or fallback to SP env variables.
       If running the application externally (not from within Azure) it will likely 
       fallback to the env variables
    """
    if "APPSETTING_WEBSITE_SITE_NAME" in os.environ:
        return MSIAuthentication(
            resource='https://vault.azure.net'
        )
    else:
        return ServicePrincipalCredentials(
            client_id=os.environ['AZURE_CLIENT_ID'],
            secret=os.environ['AZURE_CLIENT_SECRET'],
            tenant=os.environ['AZURE_TENANT_ID'],
            resource='https://vault.azure.net'
        )

#Get secret from key vault
def get_secret(secret_name):
    # Get credentials
    credentials = get_key_vault_credentials()

    # Create a KeyVault client
    key_vault_client = KeyVaultClient(credentials)
    key_vault_uri = os.environ.get("KEY_VAULT_URI", KEY_VAULT_URI)
    secret = key_vault_client.get_secret(key_vault_uri,secret_name,"")
    return(secret)
#Error function
def upsError(myError):
    #sys.exit(myError)
    response = open(os.environ['res'], 'w')
    response.write(myError)
    response.close()
    sys.exit()
    
#Function to convert UTC timestamp to desired time zone  
def TimestampConverter(utcTimeStamp, to_zone):
    timeStamp = parser.parse(utcTimeStamp).astimezone(to_zone).replace(tzinfo=None)
    return timeStamp

KEY_VAULT_URI = 'https://generationkeyvault-p.vault.azure.net/'
#Get Key Vault PI Credential's secret
secret = get_secret("PI-Credentials")
#Get secret value
credetials = secret.value


#Get credentials and add request's headers
PI_api_url_base = "https://pidata.enmax.com:450/piwebapi/"
auth = "Basic %s" % credetials
headers = {'Content-Type': 'application/json',
           'Authorization': auth }

#Get user inputs
#inputData = json.loads(open(os.environ['req']).read())

#element = inputData["name"]
element = "GGCG"
elementPath = "\\\\AFProdCollective\\GWE AF Prod\\zz System\\App Data\\Aug Reality\\%s" % element
to_zone = tz.gettz("America/Edmonton")
#elementhPath = "\\\\" + inputData["AF Path"]
valueTime = datetime.datetime.now(tz=to_zone)
nameFilter = "*"
categoryName = ""
templateName = ""

'''
to_zone = tz.gettz(inputData["Time Zone"])
elementhPath = "\\\\" + inputData["AF Path"]
valueTime = datetime.datetime.now(tz=to_zone)
nameFilter = inputData["Name Filter"]
categoryName = inputData["Category Name"]
templateName = inputData["Template Name"]
'''
#API selected fields
selectedFields = "Items.Name;Items.Value.Timestamp;Items.Value;Items.Value.Good"

# Check category and template inputs
if categoryName == "*" or categoryName == "":
    categoryName = ""
else: 
    categoryName = "categoryName=%s&" % categoryName
    
if templateName == "*" or templateName == "":
    templateName = ""
else: 
    templateName = "templateName=%s&" % templateName

#Get Element Web ID
url_base_PI = "%s/elements?path=%s" % (PI_api_url_base,elementPath)
webIDURL = "%s&selectedFields=WebId"% (url_base_PI )
response = requests.get(webIDURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))
webID = object['WebId']

#URL for streamsets current values
URLAFValues = '%sstreamsets/%s/value?time=%s&nameFilter=%s&%s%sselectedFields=%s' % (PI_api_url_base,webID,valueTime,nameFilter,categoryName,templateName,selectedFields)
#Get data
response = requests.get(URLAFValues, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))

#Number of attributes returned
NoColumns = len(object['Items'])

column = 0
data = {'TimeStamp' : str(valueTime) }

# Modified data to flatten Dictionary 
while column < NoColumns:
    if object['Items'][column]['Value']['Good']: #Check if value is good
        value = object['Items'][column]['Value']['Value']
        if isinstance(value,dict): #Check if value is a digital state value, if true return the digital value Name
            data[object['Items'][column]['Name']] = object['Items'][column]['Value']['Value']['Name']
        else:
            data[object['Items'][column]['Name']] = object['Items'][column]['Value']['Value']
    else:
        data[object['Items'][column]['Name']] = None
    column += 1

#Convert dictionary to JSON
data_output = json.dumps(data)

#HTTP call output
response = open(os.environ['res'], 'w')
response.write(data_output )
response.close()


'''
import json
import requests
import os
from dateutil import tz,parser
import sys
import datetime
import logging
#import azure.functions
#import azure.functions as func
#import pip

#pip.main(['install','msrestazure'])

from msrestazure.azure_active_directory import MSIAuthentication, ServicePrincipalCredentials
from azure.keyvault import KeyVaultClient


KEY_VAULT_URI = 'https://generationkeyvault-p.vault.azure.net/'

#Authenticate function with key vault
def get_key_vault_credentials():
    """This tries to get a token using MSI, or fallback to SP env variables.
       If running the application externally (not from within Azure) it will likely 
       fallback to the env variables
    """
    if "APPSETTING_WEBSITE_SITE_NAME" in os.environ:
        return MSIAuthentication(
            resource='https://vault.azure.net'
        )
    else:
        return ServicePrincipalCredentials(
            client_id=os.environ['AZURE_CLIENT_ID'],
            secret=os.environ['AZURE_CLIENT_SECRET'],
            tenant=os.environ['AZURE_TENANT_ID'],
            resource='https://vault.azure.net'
        )

#Get secret from key vault
def get_secret(secret_name):
    # Get credentials
    credentials = get_key_vault_credentials()

    # Create a KeyVault client
    key_vault_client = KeyVaultClient(credentials)
    key_vault_uri = os.environ.get("KEY_VAULT_URI", KEY_VAULT_URI)
    secret = key_vault_client.get_secret(key_vault_uri,secret_name,"")
    return(secret)

#Get Key Vault PI Credential's secret
secret = get_secret("PI-Credentials")
#Get secret value
credetials = secret.value


#postreqdata = json.loads(open(os.environ['req']).read())
#message = "Using Python '{0}'".format(platform.python_version())
response = open(os.environ['res'], 'w')
#response.write(str(credetials))
response.write(str({
            'method': "test1",
            'url': "www.mytest.com"
        }))
response.close()

'''