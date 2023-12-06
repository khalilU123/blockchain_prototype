import requests
import json

url = 'http://localhost:8000/new_transaction'
url2='http://localhost:8000/mine'
url3='http://localhost:8000/chain'
url4='http://localhost:8000/print_chain'
medical_record = {
    "patientID": "John Doe",
    "doctor": "Dr. Smith",
    "hospital": "ABC Hospital",
    "diagnosis": "Hypertension",
    "medication": [
        {
            "medication_id": "12345",
            "medication_name": "Lisinopril"
        },
        {
            "medication_id": "67890",
            "medication_name": "Metoprolol"
        }
    ]
}

headers = {'Content-Type': 'application/json'}
response = requests.post(url, data=json.dumps(medical_record), headers=headers)
response1 = requests.get(url2, headers=headers)
response3 = requests.get(url3, headers=headers)
print(response3.json())
# if response.status_code == 200:
#     print("Medical record successfully sent!")
# else:
#     print("Error occurred while sending medical record.")
#     print("Status Code:", response.status_code)
#     print("Response:", response.text)
