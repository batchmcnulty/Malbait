#!/usr/bin/python3



#def send_simple_message(from_address, to_address, smtp_server, smtp_port, email_password, mailtext):
def send_simple_message(from_address, to_address, smtp_server, smtp_port, email_password, report_filename):
	import smtplib, ssl
	from os.path import basename
	from email.mime.application import MIMEApplication
	from email.mime.text import MIMEText
	from email.mime.multipart import MIMEMultipart
	from email.header import Header
	from email.utils import formataddr

	report_handle = open(report_filename, 'r')
	mailtext = report_handle.read()
	
	Recipient = to_address
	msg = MIMEMultipart('alternative')
	msg['Subject'] = "Malbait has logged a connection!"
	msg['From'] = formataddr((str(Header('Malbait', 'utf-8')), from_address))
	msg['To'] = Recipient
	part1 = MIMEText(mailtext, 'plain')
	msg.attach(part1)

	'''
	handle = open("fuckflaps.txt","a")
	print ("FROM	TO		SMTP SERVER		SMTP PORT	email_password	TEXT", file = handle)
	print (from_address, to_address, smtp_server, smtp_port, email_password, mailtext, sep = "\t", file = handle)
	print ("-------------------------------------------------------------------------_", file = handle)
	print ("msg:", msg, file = handle)
	handle.close()
	'''
	# uncommment when its time to install
	server = smtplib.SMTP(smtp_server, smtp_port)
	context = ssl.create_default_context()
	server.starttls(context=context) # Secure the connection
	server.login(from_address, email_password)
	server.sendmail(msg['From'], msg['To'], msg.as_string())
	server.quit() 

########################### MAIN ##########################################

import sys
import os

print (sys.argv);


#quit()
from_address = sys.argv[1]
to_address = sys.argv[2]
smtp_server = sys.argv[3]
smtp_port = sys.argv[4]
email_password = sys.argv[5]
report_filename = sys.argv[6]
#report_handle = open(report_filename, r)
#mailtext = report_handle.read()

'''
attach_filename = sys.argv[7]
attachtext = "Attachments are a hassle. Not even sure this does anything!"
attachfile = open (attach, "a")
print (attachtext, file = attachfile)
attachfile.close()
'''
#print (mailtext)
print ("Contents of", report_filename,"will be sent to ",to_address)
#send_simple_message(from_address, to_address, smtp_server, smtp_port, email_password, mailtext)
send_simple_message(from_address, to_address, smtp_server, smtp_port, email_password, report_filename)
