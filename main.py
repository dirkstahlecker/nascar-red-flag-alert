from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import smtplib, ssl

def parseConfigVar(input):
	return input[input.index(":") + 1 : ].strip();

configs = open('config.txt').read()
configs = configs.split("\n")
receiver_email = parseConfigVar(configs[0])
chromedriver_path = parseConfigVar(configs[1])

print(receiver_email)
print(chromedriver_path)

password = sys.argv[1]
port = 465  # For SSL
smtp_server = "smtp.gmail.com"
sender_email = "sendmailprogrammatically@gmail.com"  # Enter your address
# password = input("Type your password and press enter: ")
msg = MIMEMultipart("alternative")
msg["Subject"] = 'Red Flag Has Been Lifted'
msg["From"] = receiver_email
msg.attach(MIMEText('\nsent via python', 'plain'))


#for testing
INITIAL_STATE = "flag-red"
WANTED_STATE = "flag-caution"

print("Initial state: " + INITIAL_STATE)
print ("Looking for: " + WANTED_STATE)


URL = sys.argv[2] #take URL from command line

driver = webdriver.Chrome(executable_path=chromedriver_path)
# driver = webdriver.Chrome()
driver.implicitly_wait(10)
driver.get(URL)
assert "NASCAR" in driver.title

def main():
	elem = driver.find_element_by_class_name(INITIAL_STATE)
	#should find red initially

	if (not elem):
		print ("Initial state not found.")
		return

	while True:
		try:
			elem = driver.find_element_by_class_name(WANTED_STATE)
			sendMessage()
			driver.close()
			return;
		except:
			#do nothing
			print("Didn't find wanted state...")
			# time.sleep(5)


def sendMessage():
	print("======================\nSENDING MESSAGE")

	# s = smtplib.SMTP(smtp_server, port)
	# s.ehlo()
	# s.starttls()
	# s.login(sender_email, password)
	# s.sendmail(sender_email, receiver_email, msg.as_string())
	# s.quit()

	server = smtplib.SMTP('smtp.gmail.com', 587) 
	server.ehlo()
	server.starttls()
	server.login(sender_email, password)  
	server.sendmail(sender_email, receiver_email, msg.as_string())  
	server.quit()


	# context = ssl.create_default_context()
	# with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
	#     server.login(sender_email, password)
	#     server.sendmail(sender_email, receiver_email, message)


main()





#nascar.red.flag.alert.dev1
#nascaralert

#run with "python3 main.py"
