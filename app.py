from flask import Flask, render_template, request, redirect, url_for, session
import random
import smtplib
from email.message import EmailMessage
import re
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'satbayev' 

EMAIL_ADDRESS = 'diastulegenov2004@gmail.com'
EMAIL_PASSWORD = 'ntouaujnwussobay'

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='diplom'
    )

def is_valid_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/send-code', methods=['POST'])
def send_code():
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    username = request.form['username']
    phone = request.form['phone']
    master_key = request.form['master_key']

    if not email or not password or not confirm_password:
        return "Поля не должны быть пустыми", 400

    if password != confirm_password:
        return "Пароли не совпадают", 400

    if not is_valid_email(email):
        return "Неверный email", 400

    hashed_password = generate_password_hash(password)

    code = str(random.randint(100000, 999999))
    session['verification_code'] = code
    session['email'] = email
    session['username'] = username
    session['phone'] = phone
    session['master_key'] = master_key
    session['password'] = hashed_password

    msg = EmailMessage()
    msg.set_content(f"Ваш код подтверждения: {code}", )
    msg['Subject'] = 'Код подтверждения'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    try:
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp_server.send_message(msg)
        smtp_server.quit()

        return render_template('verify.html')
    except smtplib.SMTPException as e:
        return f"Ошибка отправки: {e}", 500

@app.route('/verify-code', methods=['POST'])
def verify_code():
    user_code = request.form.get('confirmation_code')
    true_code = session.get('verification_code')

    if not user_code:
        return "Код не передан", 400

    if user_code == true_code:
        email = session.get('email')
        username = session.get('username')
        phone = session.get('phone')
        master_key = session.get('master_key')
        hashed_password = session.get('password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            conn.close()
            return render_template('verify.html', error="Email уже зарегистрирован")

        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, phone, master_key, password) VALUES (%s, %s, %s, %s, %s)",
            (username, email, phone, master_key, hashed_password)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('biometric_page'))
    else:
        return render_template('verify.html', error="Неверный код")


@app.route('/login-existing', methods=['GET', 'POST'])
def login_existing():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            return redirect(url_for('biometric_page'))
        else:
            return render_template('login_existing.html', error="Неверный email или пароль")

    return render_template('login_existing.html')

@app.route('/biometric')
def biometric_page():
    return render_template('biometric.html')

@app.route('/generator')
def generator():
    return render_template('generator.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
