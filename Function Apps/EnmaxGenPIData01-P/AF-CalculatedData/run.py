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

path = inputData["AF Path"]
to_zone = tz.gettz(inputData["Time Zone"])
startTime = inputData["Start Time"]
endTime = inputData["End Time"]
summaryDuration = inputData["Summary Duration"]
nameFilter = inputData["Name Filter"]
filterExpression = inputData["Filter Expression"]
categoryName = inputData["Category Name"]
templateName = inputData["Template Name"]
summaryType = inputData["Calculation Mode"]
calculationBasis = inputData["Calculation Basis"]
timeType = "EarliestTime"
selectedFields = "Items.Name;Items.Items.Timestamp;Items.Items.Value;Items.Items.Good"

#Get AF Element WebID
elementhPath = "\\\\" + path
url_base_PI = "%s/elements?path=%s" % (PI_api_url_base,elementhPath)
webIDURL = "%s&selectedFields=WebId"% (url_base_PI )
response = requests.get(webIDURL, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))
webID = object['WebId']

#Category Name and Filter Expression 
if categoryName == "*" or categoryName == "":
    categoryName = ""
else: 
    categoryName = "categoryName=%s&" % categoryName
    
if templateName == "*" or templateName == "":
    templateName = ""
else: 
    templateName = "templateName=%s&" % templateName
if filterExpression == "*":
    filterExpression = ""
else:
    filterExpression = "filterExpression=%s&" % filterExpression
  
#Build Interpolated Data URL
URLInterpolated = '%sstreamsets/%s/summary?startTime=%s&endTime=%s&summaryDuration=%s&' \
                    'nameFilter=%s&summaryType=%s&calculationBasis=%s&timeType=%s&%s%s%sselectedFields=%s' \
                     % (PI_api_url_base,webID,startTime,endTime,summaryDuration,nameFilter, \
                     summaryType,calculationBasis,timeType,filterExpression,categoryName,templateName,selectedFields)


#Get interpolated data
response = requests.get(URLInterpolated, headers=headers, verify=False)
object = json.loads(response.content.decode('utf-8'))

#lambda function gets the length or total number of values per attribute
#map is an easy way to iterate through each item/attribute and apply the lambda function
#Gets the maximum number of values or max number of rows in the dataset
#this is necesary to handle non numeric attribute values type such as digital values.
#Calculated data is applied only to numeric values
NoRows = max(map(lambda x: len(x['Items']),object['Items']))
NoColumns = len(object['Items'])
row = 0
column = 0
data = []

#Build flatten dictionary 
while row < NoRows:
    dataBuild = {}
    #Converts UTC timestamp to specified time zone 
    utcTimeStamp = object['Items'][0]['Items'][row]['Value']['Timestamp']
    dataBuild["001Timestamp"] = str(TimestampConverter(utcTimeStamp,to_zone))
    while column < NoColumns:
        #This is a way to discard those attributes with none numeric value type.
        if len(object['Items'][column]['Items']) == NoRows:
            #Checks if the value has good quality
            if object['Items'][column]['Items'][row]['Value']['Good']:
                dataBuild[object['Items'][column]['Name']] = object['Items'][column]['Items'][row]['Value']['Value']
        else:
            dataBuild[object['Items'][column]['Name']] = ""   
        column += 1
    column = 0
    row += 1
    data.append(dataBuild)  
#Convert dictionay to flatten JSON
data_output = json.dumps(data)

#HTTP call response
response = open(os.environ['res'], 'w')
response.write(data_output)
response.close()