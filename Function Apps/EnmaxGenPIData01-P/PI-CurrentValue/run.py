import json
import requests
import os
from dateutil import tz,parser
import sys
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


inputData = json.loads(open(os.environ['req']).read())


#PI Server/collective name
piCollective = "\\\%s\\" % inputData["PI Server"]

#Get PI tags and easy tag name. Easy tag name allows to return a more user friendly tag name for the data, 
#if friendly names are not provided then it returns the tag name in the data  

#Get timestamp time zone
to_zone = tz.gettz(inputData["Time Zone"])

#Get PI tags names separated by a ","
piTag = list(inputData['Tag Names'].split(","))#List of PI tags
piTag = list(map(str.strip, piTag)) #Use strip to remove blank spaces that could have been entered between names.

#Get friendly tag names for each PI tag separated by a ","
if 'Friendly Names' in inputData:
    friendlyNames = list(inputData['Friendly Names'].split(","))
    friendlyNames = list(map(str.strip, friendlyNames)) #Use strip to remove blank spaces that could have been entered between names.
else:
    friendlyNames = []
tagNames = piTag 
go = True

while go == True:
    #If friendly names are provided then check if there is a friendly name for each PI tag requested
    #if not return an error
    if friendlyNames:
        if len(piTag) != len(friendlyNames):
            upsError('There must be same number of friendly names and tag names separated by a ",". '
                     'If you do not want to add friendly names then leave Friendly Names blank.')
            break
        else:
            tagNames = friendlyNames
    go = False

#Time Now
valueTime = datetime.datetime.now(tz=to_zone)   

#Get PI Data
url_base_PI = "https://pidata.enmax.com:450/piwebapi/points?path=%s" % piCollective
data = {'TimeStamp' : str(valueTime) }

for index, tagName in enumerate(tagNames):
    #Get web ID for the PI tag.
    tag = piTag[index]
    webIDURL = "%s%s&selectedFields=WebId"% (url_base_PI, tag)
    response = requests.get(webIDURL, headers=headers, verify=False)
    object = json.loads(response.content.decode('utf-8'))
    webID = object['WebId']
    #Get current value
    getValueURI = "%sstreams/%s/value?selectedFields=Timestamp;Value;Good" % (PI_api_url_base,webID)
    response = requests.get(getValueURI, headers=headers, verify=False)
    object = json.loads(response.content.decode('utf-8'))
    

    
    #Get value
    if object['Good']:
        data[tagName] = object['Value']
    else:
        data[tagName] = None
    

output = json.dumps(data)

#Return data
response = open(os.environ['res'], 'w')
response.write(output)
response.close()