import re

reg_test1 = r'^(\w{3}\s+\d+\s\d{1,2}:\d{1,2}:\d{1,2})\s(\S+)\s(\w+):\s([\w+\s]*):\s(\w*),\s(\S*\s\S*)[^\/]'
reg_test2 = r'^(\<\d{1,3}\>)(\w{3}\s\d+\s\d{1,4}\s[\d:]*)\s(\S*)\s(\S*):([\w\s]*.)\s\((\w*\=[\d.]*)\,\s(\w*\=\S*)\,\s(\w*\=\w*)\,\s(\w*\=\d)\,\s(\w*\=\w*)\)'
reg_test3 = r'(\<\d{1,5}\>)(\w{3}\s{2}\d{2}\s[\d:]*)\s(.*?)\:\s(\S*)\s([\w\s]*)\:\s([\S*\s]*(ID\s\S*)\s[a-z]*.*)\s(\S*)$'
reg_test4 = r'(\d{4}[\/\d{1,2}]*\s[\d{1,2}:]*\s[A-Z]*[,\d]*)([\w\s]*)\,([\w\s]*)\,(\d{1,3})\,([\w\s]*\,[\w\@\.]*\,\S)([\S\s]*\:\s[\w\@\.]*)\s\w*\s([\w]*\s[\d{1,2}\.]*\s[\w\s]*\s[\d{1,2}\.]*)\s[[a-z]+\s]*([\w\s]*)$'
siem_data1 = {
    'Date_time': None,
    'Log_file': None,
    'Type': None,
    'Message': None,
    'Status': None,
    'Result': None
}
siem_data2 = {
    'Num': None,
    'Date_time': None,
    'Device': None,
    'Request': None,
    'Message': None,
    'IP': None,
    'VpnName': None,
    'UserName': None,
    'Times': None,
    'Reason': None
}
siem_data3 = {
    'Num': None,
    'Date_time': None,
    'Device': None,
    'ParentPartition': None,
    'User': None,
    'Message': None,
    'ID_Partition': None,
    'ServerName': None
}
siem_data4 = {
    'Date_time': None,
    'Service': None,
    'AccessStatus': None,
    'ProcessPID': None,
    'InitialUserAuthenticationStatus': None,
    'UserAuthenticationStatus': None,
    'SourceHost': None,
    'Resource': None
}
def reader(filename):
    regexp = reg_test4

    with open(filename) as f:
        log = f.read()
        siem_raw_data = re.findall(regexp, log)

    return siem_raw_data


def writer(raw_data):
    count = 0
    for key in siem_data4:
        siem_data4[key] = raw_data[0][count]
        count += 1


if __name__ == '__main__':
    writer(reader('log4.log'))
    print(siem_data4)
    for item in siem_data4:
        print(siem_data4[item])