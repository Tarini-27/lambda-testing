import pytest
import boto3,json,os,sys
import importlib

sys.path.append("..")
# print("Current wd",os.getcwd())
# os.chdir()
s3_client = boto3.client('s3')
client = boto3.client('lambda')
def get_bucket():
    response = s3_client.head_bucket(
        Bucket='sunlife-cybersec-test',
    )
    return response

def get_lambda_name(name):
    response = client.get_function(
        FunctionName=name
    )
    return response

def test_s3Upload():
    res = get_bucket()
    assert res["ResponseMetadata"]["HTTPStatusCode"] == 200

# def test_lambda():
#     res1 = get_lambda_name('sunlife-aman-lambda-test')
#     res2 = get_lambda_name('Sunlife_cyber_sec_test_1')
#     assert res1["Configuration"]["FunctionName"] == "sunlife-aman-lambda-test"
#     assert res2["Configuration"]["FunctionName"] == "Sunlife_cyber_sec_test_1"

def test_invokeLambda():
    func_name = os.environ["lambda_func_name"]
    print(os.getcwd())
    file = open("events.json", "r")
    data = json.load(file)
    event = data[func_name]
    # print(data["Sunlife_cyber_sec_test_1"]) 
    # event = {
    #         "invocationId": "invocationIdExample",
    #         "deliveryStreamArn": "arn:aws:kinesis:EXAMPLE",
    #         "region": "us-east-1",
    #         "records": [
    #             {
    #             "recordId": "49546986683135544286507457936321625675700192471156785154",
    #             "approximateArrivalTimestamp": 1495072949453,
    #             "data": "T2N0ICAxIDA5OjAxOjI2IFNWODQwNTUgZ3VhcmRfc2VuZGVyWzcyODldOiBMRUVGOjEuMHxJQk18R3VhcmRpdW18MTAuMHxBbGVydCBvbiBSZXBlYXRlZCBTUUwgRXJyb3JzfHJ1bGVJRD0yMDA3NHxydWxlRGVzYz1BbGVydCBvbiBSZXBlYXRlZCBTUUwgRXJyb3JzfHNldmVyaXR5PUlORk98ZGV2VGltZT0yMDIwLTEwLTAxIDA4OjQzOjUzfHNlcnZlclR5cGU9T1JBQ0xFfGNsYXNzaWZpY2F0aW9uPXxjYXRlZ29yeT18ZGJQcm90b2NvbFZlcnNpb249My4xNHx1c3JOYW1lPXxzb3VyY2VQcm9ncmFtPU9SQUFHRU5ULkJJTnxzdGFydD0xNjAxMTU5OTUzOTQ1fGRiVXNlcj1TWVN8ZHN0PTEwLjE1Mi4xNi4yMXxkc3RQb3J0PTU4MTI5fHNyYz0xMC4xNTIuMTYuMjF8c3JjUG9ydD0xMjg0fHByb3RvY29sPUJFUVVFQVRIfHR5cGU9U1FMX0VSUk9SfHZpb2xhdGlvbklEPTQ0MTM1MjAwMDEyNzg3MDk2NHxzcWw9QUxURVIgU0VTU0lPTiBTRVQgIl9ub3RpZnlfY3JzIiA9IGZhbHNlfGVycm9yPU9SQS0yNTIyOAo="
    #             }
    #         ]
    #     }

    
    my_mod = importlib.import_module(func_name)
    response = my_mod.lambda_handler(event,None)
    print(response)
    assert response['records'][0]['result'] == 'Ok'
    assert response['records'][0]['recordId'] == event['records'][0]['recordId'] 
    file.close()
    # os.chdir("../../")
    # print(os.getcwd())
    # json_val = json.dumps(val).encode('utf-8')

    # response = client.invoke(
    #     FunctionName='Sunlife_Main_Lambda_test',
    #     Payload= json_val,
    # )
    # res = response['Payload'].read()
    # res = res.decode('utf-8')
    # res = json.loads(res)
    # assert response['StatusCode'] == 200
    # assert res['records'][0]['recordId'] == "49546986683135544286507457936321625675700192471156785154" 

if __name__ == "__main__":
    pytest.main()