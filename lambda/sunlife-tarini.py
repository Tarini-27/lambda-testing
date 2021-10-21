'''North America Guardium code for Kinesis Firehose pipeline'''
import json
import boto3
import re
import base64
import datetime
import time
import calendar
import sl_custom_date_lib as sl_custom_dt_lib
import uuid
import os

s3 = boto3.client('s3')
'''For Failed Lines - Regex Transform'''
bucket = "sunlife-cyber-security-firehose"
folder_name = "Firehose_test_guardiam/error/Guardium/lambda-regex-transformation-failed/"


def get_ip_int(ip):
	'''
	Returns str equivalent of IP address received in str format
	'''
	'''Do the conversion of ips to bigint in the glue job'''
	try: 
		return str((int(ip.split(".")[0]) * int("16777216")) + (int(ip.split(".")[1]) * int("65536")) + (int(ip.split(".")[2]) * int("256")) + int(ip.split(".")[3]))
	except:
		return None

def lambda_handler(event, context):
	#items = []
	success_jsons_counter = 0
	failed_lines = []
	failed_lines_counter = 0
	Raw_RecordCount = 0
	Empty_LineCount = 0
	outputRecords = []
	region = "north america"
	
	'''Required fields'''
	required_fields = ['Date', 'ServerID', 'guard_sender', 'ruleID', 'ruleDesc', 'severity', 'devTime', 'serverType', 'classification', 'category', 'dbProtocolVersion', 'userName', 'sourceProgram', 'start','databaseName', 'dbUser', 'dst', 'dstPort', 'src', 'srcPort', 'protocol', 'type', 'violationID', 'sql', 'error']
	
	short_re = "^([a-zA-Z]{3})\s+(\d{1,2})\s+(\d{1,2}:\d{1,2}:\d{1,2})\s([^\s]+)\s+?(.*)\|(ruleID.*)$"
	
	repeated_key_value_re = r'\s*(.*?)\s*=\s*(.*?)\s*(?:\||$)'
	
	
	domain_case = r'(([^\s]*)\\)+(.*)'
	
	domain_patterns = ['su', 'ml','bm','ca','hk','id','ie','ph','us']
	domain_underscore_patterns = ['su', 'ml','bm','ca','hk','id','ie','ph','us','admin', 'ro']
	'''domain_pattern_with_underscore = r'^([^\s]*)_(.)*'''
	domain_pattern_with_underscore = r'([^\s]*)_([^\s]*)'
	acf2_pattern = r'([a-zA-Z]+[0-9]+$)'

	passu_pattern = r'^([^\s]*)(passu)'
	
	sunlife_domain_pattern1 = r'^([^\s]*)(slfcorp)$'
	sunlife_domain_pattern2 = r'^([^\s]*)(sunlife)$'
	sunlife_domain_pattern3 = r'^([^\s]*)(sunlife_ph)$'

	email_pattern = r'((^[a-zA-Z0-9_.+-]+)@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
	
	def  customserializer(o):
		if isinstance(o, datetime):
			return o.__str__()
			
	
	def get_s3_failed_folder_structure():
		
		dt = datetime.datetime.now()
		filename = get_s3_failed_filename()
		#print(filename)
		foldername = folder_name+str(dt.strftime("%Y"))+'/'+str(dt.strftime("%m"))+'/'+str(dt.strftime("%d"))+'/'+str(dt.strftime("%H"))+'/'+str(filename)
		#print(str(foldername))
		return str(foldername)
		
	def get_s3_failed_filename():
		
		if context.aws_request_id:
			return str(time.time())+'_'+context.aws_request_id+'.log' 
		else:
			return(str(time.time())+'_'+str(uuid.uuid4()) +'.log')
        #return str(time.time())+'_'+context.aws_request_id+'.log'    # ----- (new change)
        
	def user_field_cleaning(user_original):
		
		user_parsed = ''

		if user_original:
			
			user_parsed = user_original
			
			user = user_parsed
			
			if user_original == "?":
				user_parsed = "null"
			
			else:
				if len(user)>=5:	
					
					user_matching = re.match(domain_case,user_parsed)
					
					if user_matching is not None:
							
						user_parsing = user_matching.group(3)
						
						user_parsed = user_parsing
						
					
					
					user_underscore_match = re.match(domain_pattern_with_underscore, user_parsed)
					
					if user_underscore_match is not None:
						
						group_1 = user_underscore_match.group(1)
						group_2 = user_underscore_match.group(2)
							
						
						if re.match(acf2_pattern, group_1):
							'''print("ACF2 at beginning with appended underscore and some alphanumericvalues matched, eg: KF84_ml, KF84_tab")'''
							user_parsing = user_underscore_match.group(1)
							user_parsed = user_parsing
							'''print(user_parsed)'''
							
						if re.match(acf2_pattern, group_1) and (group_2 == "" or group_2 is None):
							'''print("ACF2 at beginning with only an appended underscore, KF84_ml")'''
							user_parsing = user_underscore_match.group(1)
							user_parsed = user_parsing
							'''print(user_parsed)'''
						
						'''Matching case like RO_KF84, ML_KF84 etc'''
						if group_1 in domain_underscore_patterns and re.match(acf2_pattern, group_2):
							'''print("ACF2 appended after domain or some alphanumericvalue and underscore, eg: RO_KF84, ML_KF84, SU_KF84")'''
							user_parsing = user_underscore_match.group(2)
							user_parsed = user_parsing
							'''print(user_parsed)'''
						
						
					passu_match = re.match(passu_pattern, user_parsed)
				
					if passu_match is not None:
						
						user_parsing = passu_match.group(1)
						
						user_parsed = user_parsing
						
					
					
					user_sunlife_domain_match1 = re.match(sunlife_domain_pattern1, user_parsed)
					
					user_sunlife_domain_match2 = re.match(sunlife_domain_pattern2, user_parsed)
					
					user_sunlife_domain_match3 = re.match(sunlife_domain_pattern3, user_parsed)
							
					if user_sunlife_domain_match1 is not None:
						'''print("suser_sunlife_domain_match1")'''
						user_parsing = user_sunlife_domain_match1.group(1)
						
						user_parsed = user_parsing
						
					if user_sunlife_domain_match2 is not None:
						'''print("suser_sunlife_domain_match2")'''
						user_parsing = user_sunlife_domain_match2.group(1)
						'''item["suser_parsed"] = suser_parsed'''
						user_parsed = user_parsing
						
					if user_sunlife_domain_match3 is not None:
						'''print("suser_sunlife_domain_match3")'''
						user_parsing = user_sunlife_domain_match3.group(1)
						'''item["suser_parsed"] = suser_parsed'''
						user_parsed = user_parsing
						
					length = len(user_parsed)
					'''length = len(item["suser_parsed"])'''
	
					'''Max Length of ACF2s is 7'''
					if length<=9:
						'''last_two_chars = item["suser_parsed"][length - 2 :]'''
						last_two_chars = user_parsed[length - 2 :]
						'''print(suser)'''
						'''print(last_two_chars)'''
						
						for pattern in domain_patterns:
							if last_two_chars == pattern:
								'''print("matched")'''
								'''Acf2s can be upto 7 chars -> Only remove last two chars - Domain pattern match'''
								'''item["suser_parsed"] = item["suser_parsed"][:length-2]'''
								user_parsed = user_parsed[:length-2]
								'''print(suser)'''
								'''print(item["suser_parsed"])'''
					
					# user_acf2_pattern_match= re.match(acf2_pattern, user_parsed)
					# if user_acf2_pattern_match is not None:
					# 	print("user_acf2_pattern_match")
					# 	if user_acf2_pattern_match.group(4) != '_':
					# 		user_parsing = user_acf2_pattern_match.group(1)
					# 		print(user_acf2_pattern_match.group(2))
					# 		'''item["suser_parsed"] = suser_parsed'''
					# 		user_parsed = user_parsing
					# 		'''print(suser)'''
					# 		'''print(item["suser_parsed"])'''
					
					'''Matching pattern for email-ids with acf2s appended --> For Cases like g788@clarica.com'''
					'''email_pattern = r'((^[a-zA-Z0-9_.+-]+)@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)' '''
					email_pattern_match = re.match(email_pattern, user_parsed)
					if email_pattern_match is not None:
						'''Check if first group is an ACF2 id or not'''
						'''If yes parse it, else store the same email id as dbuser'''
						acf2_matching = email_pattern_match.group(2)
						if re.match(acf2_pattern, acf2_matching):
							'''print("email_acf2_pattern_matched eg: KF84@sunlife.com")'''
							user_parsing = email_pattern_match.group(2)
							user_parsed = user_parsing
							'''print(user_parsed)'''

				else:
					'''item["suser_parsed"] = item["suser"]'''
					user_parsed = user_original
					
		else:
			'''item["suser_parsed"] = None'''
			user_parsed = None
			
		return user_parsed
	
	def dict_keys_remapping(item):
		
		key_remapping_dict= {'Date': 'event_datetime', 'ServerID': 'server_id', 'guard_sender': 'guard_sender_information', 'ruleID': 'rule_id', 'ruleDesc': 'rule_description', 
							'severity': 'severity', 'devTime': 'devTime', 'serverType': 'server_type', 'classification': 'issue_classification', 'category': 'category', 
							'dbProtocolVersion': 'db_protocol_version', 'userName': 'username', 'sourceProgram': 'source_program', 'start': 'session_start_name', 
							'databaseName': 'database_name', 'dbUser': 'database_username_unparsed', 'dst': 'destination_ip', 'dstPort': 'destination_port', 
							'src': 'source_ip', 'srcPort': 'source_port', 'protocol': 'connection_protocol', 'type': 'violation_type', 'violationID': 'violation_id', 
							'sql': 'sql_string', 'error': 'error_message', 'Other': 'unparsed_data', 'dbUser_parsed': 'database_username'}

		for key, value in key_remapping_dict.items():
			for k, v in item.items():
				item[value] = item.pop(k)
				break

		
		return item

	def create_encoded_output_record(record,item):
		
		
		'''If value is None in Dictionary --> Change it to a blank string'''
		for k, v in item.items():
			if v is None:
				item[k] = ""
		
		
		#corrected_dict = { k.replace(':', ''): v for k, v in ori_dict.items() }    
		corrected_item1 = { k.replace('/', ''): v for k, v in item.items()}
		corrected_item2 = { k.replace('-', '_'): v for k, v in corrected_item1.items() }
		'''Replacing "" double quotes in values with whitepace'''
		corrected_item3 = {k: v.replace('"', ' ') for k, v in corrected_item2.items()}
		
		
		items = json.dumps(corrected_item3, default=customserializer)
		
		'''replacing empty strings to nulls'''
		items = items.replace('""', '"null"')
		items = items.replace('null', '"null"')
		'''replacing single quotes with double quotes'''
		#items = items.replace("'",'"')
		items = items.replace('""', '"')
		
		
		
		'''Base64 encoding the dictionary'''
		base64encoded_items = base64.b64encode(items.encode('utf-8')).decode('utf-8')
		
		output_record = {
			'recordId': record['recordId'],
			'result': 'Ok',
			'data': base64encoded_items
			
		}
		
		outputRecords.append(output_record)
		'''print(outputRecords)'''
	
	#print(type(event['records']))

	for record in event['records']:
		##Initializing Empty Dictionary with key values
		item = dict([(i,None) for i in required_fields])
		item['Other'] = ""
		
		Raw_RecordCount = Raw_RecordCount + 1
		
		'''Decoding base64 encoded data record line'''
		payload = base64.b64decode(record['data'])

		'''Converting bytes to string - UTF8'''
		payload = str(payload, 'UTF-8')
		
		'''Replacing any newline strings in payload string'''
		payload = payload.replace("\n"," ")
		
		'''Extracting year from record arrival timestamp'''
		recordts_yy = sl_custom_dt_lib.get_current_year_from_record_arrivalTimestamp(record['approximateArrivalTimestamp'])
		'''print(recordts_yy)'''
		'''Extracting month from record arrival timestamp'''
		recordts_mm = sl_custom_dt_lib.get_current_month_from_record_arrivalTimestamp(record['approximateArrivalTimestamp'])
		'''print(recordts_mm)'''
		'''Extracting day from the arrival timestamp'''
		recordts_dd = sl_custom_dt_lib.get_current_day_from_record_arrivalTimestamp(record['approximateArrivalTimestamp'])
		'''print(recordts_dd)'''
		
		'''originalstrings.append(payload)'''
		
		'''Matching record line to the regex pattern'''
		matches_short = re.match(short_re, payload)
		if matches_short is not None:
			
			'''Extracting Month, Day and Timestamp and concatenating it to the Temp_Timestamp variable'''
			Temp_Timestamp = matches_short.group(1)+'-'+matches_short.group(2)+' '+matches_short.group(3)
			
			'''Concatenating year and Temp_Timestamp to the Date field'''
			item["Date"] = recordts_yy + '-' + datetime.datetime.strptime( Temp_Timestamp, "%b-%d %H:%M:%S").strftime("%m-%d %H:%M:%S")
			item["ServerID"] = matches_short.group(4)
			item["guard_sender"] = matches_short.group(5)


			'''Matching key values pairs from the group(6) of short_re to the defined regex pattern'''
			matches_key_value = re.findall(repeated_key_value_re, matches_short.group(6))
			if matches_key_value is not None:
				present_fields = dict(matches_key_value)
				
				'''checking for dbUser and userName field and standardising it'''
				try:
					present_fields["dbUser"] = present_fields["dbUSer"]
					del present_fields["dbUSer"]
				except:
					present_fields["dbUser"] = present_fields["dbUser"]
				try:
					present_fields["userName"] = present_fields["usrName"]
					del present_fields["usrName"]
				except:
					present_fields["userName"] = present_fields["userName"]
				
				'''Converting start time to seconds precision, removing ms precision'''
				Temp_Timestamp = datetime.datetime.fromtimestamp(float(present_fields['start']) / 1000 ).strftime("%Y-%m-%d %H:%M:%S")
				'''print(Temp_Timestamp)'''
				present_fields['start'] = Temp_Timestamp
				
				'''Removing common fields present in item and present_fields and storing remaining in other_fields'''
				other_fields = set(present_fields) - set(item)
				other = {}
				'''Storing key value pairs for those fields in the other dictionary and removing it from the present_fields dictionary'''
				for other_field in other_fields:
					other[other_field] = present_fields[other_field]
					del present_fields[other_field]
				
				'''Concatenating both dictionaries'''	
				item = {**item, **present_fields}
				item["Other"] = str(other)
				
				for k, v in item.items():
					if v is not None:
						item[k] = v.strip()
				'''print(item)'''
				
				
				if item["dbUser"]:
					'''print(item["dbUser"])'''
					item["dbUser"] = item["dbUser"].lower()
					'''print(item["dbUser"])'''
					item["dbUser_parsed"] = user_field_cleaning(item["dbUser"])
					'''print(item["dbUser_parsed"])'''
					
				
				'''print("printing before remapping")'''
				'''print(item)'''
				item = dict_keys_remapping(item)
				'''print("printing remapped items")'''
				'''print(item)'''
					
				'''Adding region, aws year, month, day and ip int fields'''
				item["log_source_region"] = region
				item["source_ip_int"] = get_ip_int(item["source_ip"])
				item["destination_ip_int"] = get_ip_int(item["destination_ip"])
				item["year"] = recordts_yy
				item["month"] = recordts_mm
				item["day"] = recordts_dd
				
				
				'''Encoding the parsed key-value pairs and creating final output record to
				be returned to Kinesis Firehose'''
				create_encoded_output_record(record,item)
				success_jsons_counter +=1
				
			else:
				if len(payload.strip()) > 0:
					failed_lines.append(payload)
					failed_lines_counter +=1
				else:
					Empty_LineCount += 1

		else:
			if len(payload.strip()) > 0:
				failed_lines_counter +=1
				failed_lines.append(payload)
			else:
				Empty_LineCount += 1
			
	'''Handling failed lines'''
	if failed_lines_counter > 0:
		if len(failed_lines) !=0:
			
			try:
				print(f"******Failed line {failed_lines_counter}, failed_lines size {len(failed_lines)}")
				'''Dynamic folder creation for failed records'''
				foldername = get_s3_failed_folder_structure()
				'''print(foldername)'''
				'''Storing files in required S3 folder'''
				s3.put_object(ACL='bucket-owner-full-control',Bucket=bucket,Key=(foldername), Body="\n".join(failed_lines))
			except Exception as ex:
				print("Exception while writing to regex failed lines - error file...")
				print(ex)

	# if Raw_RecordCount == (success_jsons_counter + failed_lines_counter + Empty_LineCount):
	# 	if context.aws_request_id:
	# 		print("Processed the log record for request id ({}) and the # of raw log lines ({}) = The Successful Lines ({}) + Failed Lines ({}) + Empty Line({}).".format(context.aws_request_id,Raw_RecordCount, success_jsons_counter, failed_lines_counter, Empty_LineCount))
	# 	else:
	# 		print("Processed the log record for request id ({}) and the # of raw log lines ({}) = The Successful Lines ({}) + Failed Lines ({}) + Empty Line({}).".format(str(uuid.uuid4()),Raw_RecordCount, success_jsons_counter, failed_lines_counter, Empty_LineCount))
	# else:
	# 	if context.aws_request_id:
	# 		print("Possible Missing Data Alert: Processed the log record for request id ({}) and the # of raw input lines ({}) != The Successful Lines ({}) + Failed Lines ({}) + Empty Line({}).".format(context.aws_request_id,Raw_RecordCount, success_jsons_counter, failed_lines_counter, Empty_LineCount))
	# 	else:
	# 		print("Possible Missing Data Alert: Processed the log record for request id ({}) and the # of raw input lines ({}) != The Successful Lines ({}) + Failed Lines ({}) + Empty Line({}).".format(str(uuid.uuid4()),Raw_RecordCount, success_jsons_counter, failed_lines_counter, Empty_LineCount))

	
	return {'records': outputRecords}	
	
	
	
		


        
