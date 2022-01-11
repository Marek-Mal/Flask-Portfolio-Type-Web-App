from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, TextAreaField, BooleanField, PasswordField, IntegerField
from wtforms.validators import Length, Email, InputRequired, DataRequired
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.file import FileField, FileRequired
from werkzeug.utils import secure_filename
import hashlib
import binascii
import smtplib
import datetime
from urllib.parse import urlparse, urljoin
from flask_sqlalchemy import SQLAlchemy
import os,sys
from dotenv import load_dotenv
from contact import contact_
from random import randint

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Wejście Na tą stronę wymaga Zalogowania'
randcode = randint(1000000, 9999999)

e_email = os.getenv('PLSWORKEMAIL')
mymail = os.getenv('myMail')
e_password = os.getenv('PLSWORKPASSWORD')

class Contact:

    def __init__(self, FirstName, SecName, message, checkbox):
        self.FirstName = FirstName
        self.SecName = SecName
        self.message = message
        self.checkbox = checkbox

class ContactForm(FlaskForm):

    FirstName = StringField('Imię', validators=[InputRequired('Podaj Imię'), Length(min=1, max=20, message="Twoje Imię Nie spełnia wymagań")])
    SecName = StringField('Nazwisko', validators=[InputRequired('Podaj Nazwisko'), Length(min=1, max=30, message="Twoje Nazwisko nie spełnia wymagań")])
    Topic = StringField('Temat', validators=[InputRequired('Podaj Temat'), Length(min=1, max=30, message="Twój Temat nie spełnia wymagań")])
    message = TextAreaField('Twoja Wiadomość Do Mnie', validators=[InputRequired('To Pole jest wymagane!'), Length(min=5, message="Twoja Wiadomość Nie spełnia wymagań")])
    checkbox = BooleanField('Tak Zgadzam się Na Wysłanie Moich danych na adres Email', default="checked", validators=[DataRequired('To Pole Jest Wymagane')])

# USER SESSION

class User(db.Model, UserMixin):
    name = db.Column(db.String(30), unique=True, primary_key=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    subscribe = db.Column(db.Boolean)

    def __repr__(self):
        return '{} / {}'.format(self.email, self.name)

    def get_id(self):
        return self.name

    def get_hash_password(password):
        os_urrandom_static = b'+\xd6A\x86i*\x17\x08\xe6\x83;\xc5\x00\x8fY4V(\x9b\x99\xdcV\x84\x94\xe8E\xeb`\xe8\x07\xab2\xd6\x1c\x9ac\xe8\xb9\xbd\x81XK\xf5T>\xabr0\xd0\xe1^za\x07)\xe9\x8c\x81\xd5\xd3'
        salt = hashlib.sha256(os_urrandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(stored_password_hash, provided_password):
        salt = stored_password_hash[:64]
        stored_password = stored_password_hash[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000) 
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    content = db.Column(db.Text)

@login_manager.user_loader
def load_user(name):
    return User.query.filter(User.name == name).first()

def is_url_safe(target):
    ref_url = urlparse(request.host_url)
    test_url =  urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc

class LoginForm(FlaskForm):
    name = StringField('Nazwa Użytkownika', validators=[InputRequired('Niepoprawna Nazwa Użytkownika')])
    password = PasswordField('Hasło', validators=[InputRequired('Niepoprawne Hasło')])
    remember = BooleanField('Zapamiętaj Mnie')


class RegisterForm(FlaskForm):
    name = StringField('Nazwa Użytkownika', validators=[InputRequired('Użytkownik o takjej nazwie już istnieje'), Length(min=2, max=20, message="Twoja Nazwa Nie spełnia wymagań")])
    password = PasswordField('Hasło', validators=[Length(min=8, max=30, message="Hasło Musi mieć od 8 do 30 znaków")])
    password2 = PasswordField('Powtóż Hasło', validators=[Length(min=8, max=30, message="Hasło Musi mieć od 8 do 30 znaków")])
    email = EmailField('Email', validators=[InputRequired('Niepoprawny Email')])
    verify = IntegerField()




#ROUTES
@app.route('/', methods=['GET', "POST"])
def index():
    return render_template( 'WebPages/index.html', Page_Title='Strona Główna', maindiv='Strona Główna!!')

@app.route('/Doswiadczenie')
def xp():
    return render_template( 'WebPages/expirience.html', Page_Title='Doświadczenie', maindiv='Doświadczenie!!'  )


@app.route('/Kontakt', methods=["POST", "GET"])
@login_required
def contact():

    con = Contact(FirstName='', SecName='', message='', checkbox=True)
    form = ContactForm(obj=con)

    if form.validate_on_submit(): 

        try:
            contact_(current_user.name)
            flash('Twój email Został Wysłany')
            return redirect(url_for('index'))
        except:
            flash('Coś poszło nie tak')
            return redirect( url_for('contact'))

    return render_template( 'WebPages/Contact.html', Page_Title='Kontakt', maindiv='Kontakt', form=form )


@app.route('/login', methods=["POST", "GET"])
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user= User.query.filter(User.name == form.name.data).first()
        if user!= None and User.verify_password(user.password, form.password.data):
            login_user(user)
            flash('Zalogowano Pomyślnie')

            next = request.args.get('next')
            if next:
                return redirect(next)

            return redirect( url_for('index') )
        else:
            flash('Nieprawidłowe Hasło / Nazwa Użytkownika')
            return redirect( url_for('login') )


    return render_template( 'WebPages/login.html', Page_Title='Login', maindiv='Zaloguj Się!!', form=form)





@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    flash('Wylogowano Pomyślnie')
    return redirect( url_for('index') )






@app.route('/register', methods=["POST", "GET"])
def register():

    form = RegisterForm()

    if form.validate_on_submit():
        PasswordUser = form.password.data
        PasswordUser2 = form.password2.data

        if PasswordUser == PasswordUser2:
            NewUser = User.query.filter(User.name == form.name.data).first()
            EmailUser = User.query.filter(User.name == form.email.data).first()
            if NewUser == None and form.name.data != 'Admin' and EmailUser == None:
                
                name = form.name.data
                password = form.password.data
                email = form.email.data
                subscribe = False

                messagee = '''From: {}
Subject: {}
{}
'''.format('VERIFY YOUR ACCOUNT','CODE: ', randcode)
                server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
                server.ehlo()
                server.login(e_email, e_password)
                server.sendmail(form.email.data, email, messagee)
                server.close()
                
                return render_template( 'Webpages/verify.html', randcode=randcode, form=form, name=name,password=password, email=email, subscribe=subscribe)
            else:
                flash('Istnieje już Użytkownik o takiej nazwie / Adresie Email')
                return render_template( 'WebPages/register.html', Page_Title='Register', maindiv='Zerejejstruj Się!!', form=form) 
        else:
            flash('Hasła się różnią')
            return render_template( 'WebPages/register.html', Page_Title='Register', maindiv='Zerejejstruj Się!!', form=form)    
    else:
        return render_template( 'WebPages/register.html', Page_Title='Register', maindiv='Zerejejstruj Się!!', form=form)

@app.route('/Verify', methods=['POST'])
def Verify():

    form = RegisterForm()

    q = request.query_string.decode('utf-8')
    z = q.split('&')
    namee = z[0]
    a = namee.split('chart=')
    name = a[1]

    h = q.split('&')
    passwordd = h[1]
    j = passwordd.split('chart=')
    password = j[1]
    
    e = q.split('&')
    emaill = e[2]
    r = emaill.split('chart=')
    emailr = r[1]
    email = emailr.replace('%40', '@')
    
    t = q.split('&')
    sub = t[3]
    i = sub.split('chart=')
    subscribe = i[1]

    arr = [name, email, password,subscribe]
    
    if randcode == form.verify.data:
        user = User(name=name, password=User.get_hash_password(password), email=email, subscribe=False)
        db.session.add(user)
        db.session.commit()
        db.session.close()
        flash('Utworzono Konto Pomyślnie')
        return redirect( url_for('index') )
    else:
        flash('Błędny Kod')
        return redirect( url_for('register'))

@app.route('/Blog', methods=["GET", 'POST'])
def Blog():

    posts = Blogpost.query.all()

    return render_template( 'WebPages/blog.html', Page_Title='Blog', maindiv='Blog', posts=posts)

@app.route('/Blog-add', methods=["GET", 'POST'])
@login_required
def Blogadd():
    if current_user.name == 'admin':
        return render_template( 'WebPages/blogadd.html', Page_Title='Dodaj Post', maindiv='Dodaj Post')
    else:
        flash('Nie Posiadasz uprawnień')
        return redirect(url_for('index'))

@app.route('/addpost', methods=['POST'])
@login_required
def addpost():
    title = request.form['title']
    subtitle = request.form['subtitle']
    content = request.form['content']

    post = Blogpost(title=title, subtitle=subtitle, content=content)

    db.session.add(post)
    db.session.commit()
    db.session.close()
    flash('Utworzono post Pomyślnie')

    return redirect(url_for('index'))

@app.route('/post/<int:post_id>')
def post(post_id):
    post = Blogpost.query.filter_by(id=post_id).one()

    return render_template('WebPages/post.html', post=post, Page_Title='Szczegóły', maindiv='Szczegóły')

if __name__ == '__main__':
    app.run()