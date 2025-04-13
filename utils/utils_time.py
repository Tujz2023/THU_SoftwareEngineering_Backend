import datetime

def get_timestamp():
    return (datetime.datetime.now()).timestamp()

def float2time(time):
    return datetime.datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')

def time2float(time):
    return datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S').timestamp()