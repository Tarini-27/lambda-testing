import json
import boto3
import re
import urllib
import datetime
import calendar


## NEED TO EDIT THIS FUNCTION CODE FOR KINESIS FIREHOSE CASE FOR REQUIRED LOG SOURCE
def get_timestamp_using_year_digmonth(cal_current_year, cal_current_month, str_month, day, timestamp='00:00:00'):
    time_component = timestamp.split(":")
    month_to_dig = int(get_month_to_digit([str_month]))
    if int(get_month_to_digit([str_month]))==12 and int(cal_current_month==1):
        #Month in record log line timestamp is Dec, but reach Kinesis/EC2 on Jan, means year should be minused
        cal_current_year = cal_current_year - 1
    # print(cal_current_year)
    # print(month_to_dig)
    # print(day)
    return datetime(cal_current_year,
                        month_to_dig,
                        int(day),
                        int(time_component[0]),
                        int(time_component[1]),
                        int(time_component[2]),
                        0)
                        
## NEED TO EDIT CODE FOR KINESIS FIREHOSE CASE FOR REQUIRED LOG SOURCE
def get_datestr_with_year(cal_current_year, rest_date):
    #create date by adding missing year as string
    return cal_current_year+' '+rest_date
    
    
## NEED TO EDIT CODE FOR KINESIS FIREHOSE CASE FOR REQUIRED LOG SOURCE
def get_valid_year(cal_current_year,folder_month,str_month):
    #Find missing year of log file,check  if log_month is dec
    if str_month == 'Dec' and int(folder_month) == 1:
        yr = yr - 1
    return yr

def get_current_year_from_datetime():
    #Get current year from datetime library that is current year of server
    current_year = datetime.now().year #current year this log has no year
    return current_year
    

def get_current_year_from_record_arrivalTimestamp(recordtimestamp):
    # We separate the 'ordinary' timestamp and the milliseconds
    ts = int(recordtimestamp)
    dt = datetime.datetime.fromtimestamp(ts / 1000)
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    #print(formatted_time)
    year = dt.strftime('%Y')
    #print(year)
    
    if year is not None:
        # print('record ts year')
        # print(year)
        return year
    else:
        return get_current_year_from_datetime()

def get_current_month_from_record_arrivalTimestamp(recordtimestamp):
    # We separate the 'ordinary' timestamp and the milliseconds
    ts = int(recordtimestamp)
    dt = datetime.datetime.fromtimestamp(ts / 1000)
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    #print(formatted_time)
    month = dt.strftime('%m')
    #print(month)
    
    if month is not None:
        # print('record ts month')
        # print(month)
        return month
    else:
        return datetime.now().month
        
def get_current_day_from_record_arrivalTimestamp(recordtimestamp):
    # We separate the 'ordinary' timestamp and the milliseconds
    ts = int(recordtimestamp)
    dt = datetime.datetime.fromtimestamp(ts / 1000)
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    day = dt.strftime('%d')

    if day is not None:
        return day
    else:
        return datetime.now().day
        
def get_month_to_digit(month):
    month_to_digit = {v: k for k, v in enumerate(calendar.month_abbr)}
    #print(month_to_digit)
    ##Need to convert month which is in list to a string variable
    str_month = ''.join(month)
    return month_to_digit[str_month]
    
def get_month_to_digit_list():
    month_to_digit = {v: k for k, v in enumerate(calendar.month_abbr)}
    return month_to_digit
    
    
    
    
    
    
