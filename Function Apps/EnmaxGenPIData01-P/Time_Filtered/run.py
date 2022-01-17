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

targetObject = inputData["Target Object"]
targetServer = inputData["Target Server"]
expression = inputData["Expression"]
startTime = inputData["Start Time"]
endTime = inputData["End Time"]
summaryType = "Total"
calculationBasis = inputData["Calculation Basis"]
summaryDuration = inputData["Summary Duration"]
to_zone = tz.gettz(inputData["Time Zone"])
timeUnit = inputData['Time Unit']
filterName = inputData['Filter Name']

#Find AF object type
afObject = 'attributes' if targetObject.find('|',3,-1)>=0 else 'elements' if targetObject.find('\\',3,-1)>=0 else "assetservers"

#Get target object webID
dataSource = {'Archive':'dataservers?path=\\\\','AF': afObject +'?path=\\\\'}
targetWebIdURL = PI_api_url_base + dataSource[targetServer]+ targetObject + "&selectedFields=WebId"
response = requests.get(targetWebIdURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))
webID = object['WebId']

if summaryDuration == "*" or summaryDuration == "":
    summaryDuration = ""
else: 
    summaryDuration = "summaryDuration=%s&" % summaryDuration

#Get Data
selectedFields = "Items.Value.Value;Items.Value.Timestamp;Items.Value.Good"
timeFilterURL = PI_api_url_base + "calculation/summary?webId=%s&expression=%s&startTime=%s&endTime=%s" \
                "&summaryType=%s&calculationBasis=%s&%sselectedFields=%s" \
                % (webID,expression,startTime,endTime,summaryType,calculationBasis,summaryDuration,selectedFields)

response = requests.get(timeFilterURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))

#Time unit conversion
timeDict = {'Days':1,'Hours':24,'Minutes':1440,'Seconds':86400}
timeConversion = timeDict[timeUnit]

#Flatten data - Using List Comprehension 
#value gets converted to input time unit
#timestamp gets converted to input time zone
data = [{filterName:(value['Value']['Value'])*timeConversion, '001Timestamp':str(TimestampConverter(value['Value']['Timestamp'],to_zone))} \
         for value in object['Items'] ]

#Convert to JSON
data_output = json.dumps(data)    

#HTTP call response
response = open(os.environ['res'], 'w')
response.write(data_output)
response.close()
