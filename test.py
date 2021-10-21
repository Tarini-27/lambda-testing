import json, os
import boto3, zipfile,pytest
import logging
# from aws_logging_handlers.S3 import S3Handler
# client = boto3.client('firehose')
s3_client = boto3.client('s3')
client = boto3.client('lambda')

def get_lambda_name(name):
    response = client.get_function(
        FunctionName=name
    )
    return response

def update_lambda_func(fun_name):
    response = client.update_function_code(
                        FunctionName=fun_name,
                        S3Bucket= 'sunlife-cybersec-test',
                        S3Key= fun_name+'.zip'
                    )
    return response

def create_lambda_func(fun_name):
    response = client.create_function(
                    FunctionName=fun_name,
                    Runtime='python3.9',
                    Role='arn:aws:iam::130159455024:role/SunLifeCyberSecurity-Developer-3857',
                    Handler=fun_name+'.handler',
                    Code={
                        'S3Bucket': 'sunlife-cybersec-test',
                        'S3Key': fun_name+'.zip',
                    },
                    Timeout=123,
                    MemorySize=128,
                )
    return response

def handler():
    name1 = os.environ['name1']
    file_name = name1.split(' ')
    print(file_name)
    allowed_files = ["Lambda/sunlife-aman-lambda-test.py","Lambda/Sunlife_cyber_sec_test_1.py"]
    for name in file_name:
        if name in allowed_files:
            b_name = os.path.basename(name)
            fun_name = b_name.split('.')
            fun_name = fun_name[0]
            print(fun_name)
            try:
                print("Testing")
                os.environ["lambda_func_name"] = fun_name
                os.chdir(os.getcwd()+"/Lambda/tests/")
                res = pytest.main(["-x","test_lambda.py"])
                print(res)
                if res==0:
                    print("Test Passed")
                else:
                    return False
            except Exception as e:
                print("Error in testing",e)
                return False
            print("After Testing") 
            os.chdir("../../")   
            # print(os.getcwd())
            try:
                os.chdir(os.getcwd()+"/Lambda/")
                zip_file = zipfile.ZipFile(fun_name+'.zip','w')
                zip_file.write(b_name,compress_type=zipfile.ZIP_DEFLATED)
                zip_file.close()
                response = s3_client.upload_file(fun_name+'.zip', 'sunlife-cybersec-test', fun_name+'.zip')
                print("upload to s3 Successfull",response)
                os.chdir("..")
                

            except Exception as e:
                print("Error While uploading to s3",e)
                return False
            
            print("Calling lambda func")
            try:
                lambda_res = get_lambda_name(fun_name)
                if lambda_res:
                    response = update_lambda_func(fun_name)
                    print("updating lambda res",response)
            except Exception as e:
                print("Lambda function not there")
                print("Creating a new lambda function...")
                response = create_lambda_func(fun_name)
                print("Creating lambda res",response)

    print("Successfull")            
    return True

handler()
