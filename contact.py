import app
from flask import redirect, url_for, flash
from dotenv import load_dotenv
import smtplib, os
load_dotenv()

def contact_(currUser):

    x = app.User.query.filter(app.User.name == app.current_user.name).first()
    q = str(x)

    form = app.ContactForm()
    email = os.getenv('PLSWORKEMAIL')
    mymail = os.getenv('myMail')
    password = os.getenv('PLSWORKPASSWORD')
    messagee = '''From: {}
Subject: {}
{} / {} / {}
'''.format(currUser,form.Topic.data, form.message.data, q, form.SecName.data)
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.ehlo()
    server.login(email, password)
    server.sendmail(email, mymail, messagee)
    server.close()