import smtplib
import os
form = 'app.ContactForm()'
email = os.getenv('PLSWORKEMAIL')
mymail = os.getenv('myMail')
password = os.getenv('PLSWORKPASSWORD')
messagee = '''From: Huwdu
'''.format()
server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
server.ehlo()
server.login(os.getenv('PLSWORKEMAIL'), os.getenv('PLSWORKPASSWORD'))
server.sendmail(os.getenv('PLSWORKEMAIL'), os.getenv('PLSWORKEMAIL'), messagee)
server.close()