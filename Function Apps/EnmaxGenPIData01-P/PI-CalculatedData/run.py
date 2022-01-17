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

inputData = json.loads(open(os.environ['req']).read())


#Get Inputs
piServer = inputData["PI Server"]
to_zone = tz.gettz(inputData["Time Zone"])
tagName = inputData['PI Tag']
startTime = inputData["Start Time"]
endTime = inputData["End Time"]
timeZone = inputData["Time Zone"]
summaryDuration = inputData["Summary Duration"]
filterExpression = inputData["Filter Expression"]
summaryType = inputData["Calculation Mode"]
calculationBasis = inputData["Calculation Basis"]
timeType = "EarliestTime"
selectedFields = "Items.Value.Timestamp;Items.Value.Value;Items.Value.Good"


#Get PI tags and easy tag name. Easy tag name allows to return a more user friendly tag name for the data, 
#if friendly names are not provided then it returns the tag name in the data  
#Get friendly tag names for each PI tag separated by a ","
if 'Friendly Name' in inputData:
    friendlyName = inputData['Friendly Name']
else:
    friendlyName = tagName
    
if filterExpression == "*":
    filterExpression = ""
else:
    filterExpression = "filterExpression=%s&" % filterExpression
    
#Get PI tag webID
piCollective = "\\\%s\\" % inputData["PI Server"]
url_base_PI = "https://pidata.enmax.com:450/piwebapi/points?path=%s" % piCollective
webIDURL = "%s%s&selectedFields=WebId"% (url_base_PI, tagName)
response = requests.get(webIDURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))
webID = object['WebId']


#Get summary data
URLSummary = '%sstreams/%s/summary?startTime=%s&endTime=%s&summaryDuration=%s&summaryType=%s&calculationBasis=%s&timeType=%s&%sselectedFields=%s' \
         % (PI_api_url_base,webID,startTime,endTime,summaryDuration,summaryType,calculationBasis,timeType,filterExpression,selectedFields)
response = requests.get(URLSummary, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))

#Build flatten Dictionary
data = []
for value in object['Items']:
    dataBuild = {}
    utcTimeStamp = value['Value']['Timestamp']
    isGood = value['Value']['Good']
    #Dictionaries order Keys in ASC order. Add 001 sufix to timespamp so it appears in the first column 
    dataBuild['001Timestamp'] = str(TimestampConverter(utcTimeStamp,to_zone))
    if isGood:
        dataBuild[friendlyName] = value['Value']['Value']
    else:
        dataBuild[friendlyName] = None

    #Add data to a dictionary
    data.append(dataBuild)

#Convert dictionary to JSON
data_output = json.dumps(data)

# HTTP call output
response = open(os.environ['res'], 'w')
response.write(data_output)
response.close()