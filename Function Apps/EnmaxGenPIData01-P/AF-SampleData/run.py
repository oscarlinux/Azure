import os
import json
import requests
from dateutil import tz,parser
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
inputData = json.loads(open(os.environ['req']).read())
path = inputData["AF Path"]
to_zone = tz.gettz(inputData["Time Zone"])
startTime = inputData["Start Time"]
endTime = inputData["End Time"]
timeZone = "Mountain Standard Time"
interval = inputData["Interval"]
nameFilter = inputData["Name Filter"]
categoryName = inputData["Category Name"]
templateName = inputData["Template Name"]
selectedFields = "Items.Name;Items.Items.Timestamp;Items.Items.Value;Items.Items.Good"


#Get AF Element Web ID
elementhPath = "\\\\" + path
url_base_PI = "%s/elements?path=%s" % (PI_api_url_base,elementhPath)
webIDURL = "%s&selectedFields=WebId"% (url_base_PI )
response = requests.get(webIDURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))
webID = object['WebId']

if categoryName == "*" or categoryName == "":
    categoryName = ""
else: 
    categoryName = "categoryName=%s&" % categoryName
    
if templateName == "*" or templateName == "":
    templateName = ""
else: 
    templateName = "templateName=%s&" % templateName
    
URLInterpolated = '%sstreamsets/%s/interpolated?startTime=%s&endTime=%s&interval=%s&nameFilter=%s&%s%sselectedFields=%s' \
                % (PI_api_url_base,webID,startTime,endTime,interval,nameFilter,categoryName,templateName,selectedFields)

#Get Data
response = requests.get(URLInterpolated, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))

#Build Flatten Dictionary
NoColumns = len(object['Items'])
NoRows = len(object['Items'][0]['Items'])
row = 0
column = 0
data = []
while row < NoRows:
    dataBuild = {}
    utcTimeStamp = object['Items'][0]['Items'][row]['Timestamp']
    dataBuild["001Timestamp"] = str(TimestampConverter(utcTimeStamp,to_zone))
    while column < NoColumns:
        
        if object['Items'][column]['Items'][row]['Good']:
            dataBuild[object['Items'][column]['Name']] = object['Items'][column]['Items'][row]['Value']
        else:
            dataBuild[object['Items'][column]['Name']] = None
    
        column += 1
    column = 0
    row += 1
    data.append(dataBuild)   

#Convert dictionary to JSON
data_output = json.dumps(data)

#HTTP call output
response = open(os.environ['res'], 'w')
response.write(data_output)
response.close()