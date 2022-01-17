import os
import json
import pandas as pd
import ast
#pip.main(['install','pandas'])

inputData = open(os.environ['req']).read()
inputData = ast.literal_eval(inputData) # Convert input data to dictionary

#Get Inputs
left = inputData["Left Dataset"]
right = inputData["Right Dataset"]
how = inputData["Join Type"]

#Join Data
leftData = json.loads(left)
leftDF = pd.DataFrame(leftData)
rightData = json.loads(right)
rightDF = pd.DataFrame(rightData)
mydatdf = pd.merge(leftDF,rightDF,how=how,on='001Timestamp',left_index=True,right_index=True)
data_output = mydatdf.to_json(orient='records')

response = open(os.environ['res'], 'w')
response.write(data_output)
response.close()