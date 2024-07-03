from flask import Flask, jsonify, request, abort, render_template, session, redirect, url_for
from functools import wraps
import jwt
from jwt import InvalidTokenError
import mysql.connector
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SECRET_KEY = "VotreCléSecrèteJWT"

app = Flask(__name__)
app.secret_key = SECRET_KEY
bcrypt = Bcrypt(app)

# Configuration de la base de données
db_config = {
    'user': 'hackathon_user',
    'password': 'hackathon_password',
    'host': 'localhost',
    'database': 'hackathon_db'
}

# Configuration de l'email
SMTP_SERVER = 'smtp.gmail.com'  # Remplacez par le serveur SMTP de votre fournisseur de messagerie
SMTP_PORT = 587
EMAIL_USER = 'salah78100@gmail.com'  # Remplacez par votre adresse email
EMAIL_PASSWORD = 'votre_mot_de_passe'  # Remplacez par votre mot de passe email

def generate_pin():
    """Generate a random 6-digit PIN"""
    return ''.join(random.choices(string.digits, k=6))

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_USER, to_email, text)
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def validate_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except InvalidTokenError as e:
        print(f"JWT validation error: {e}")
        return str(e)

# Décorateur pour exiger la clé API
def require_api_key(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-API-KEY') and request.headers.get('X-API-KEY') == 'VotreCleSecrete':
            return view_function(*args, **kwargs)
        else:
            abort(401)
    return decorated_function

# Connexion à la base de données
def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

# Route d'inscription
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    created_at = datetime.now()
    updated_at = datetime.now()
    service = data.get('service')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (first_name, last_name, email, password_hash, created_at, updated_at, service)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (first_name, last_name, email, hashed_password, created_at, updated_at, service))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'status': 'success', 'message': 'User registered successfully'})

# Route pour enregistrer une carte NFC
@app.route('/register_nfc', methods=['POST'])
def register_nfc():
    data = request.json
    user_id = data.get('user_id')
    card_uid = data.get('card_uid')
    issued_at = datetime.now()
    expires_at = data.get('expires_at')  # Vous pouvez spécifier une date d'expiration si nécessaire
    status = 'active'  # Vous pouvez définir le statut initial de la carte

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO nfc_cards (user_id, card_uid, issued_at, expires_at, status)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, card_uid, issued_at, expires_at, status))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'status': 'success', 'message': 'NFC card registered successfully'})

# Route de connexion via NFC
@app.route('/nfc_login', methods=['POST'])
def nfc_login():
    card_uid = request.json.get('card_uid')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.id, users.first_name, users.last_name, users.email, users.service, users.created_at 
        FROM users 
        JOIN nfc_cards ON users.id = nfc_cards.user_id 
        WHERE nfc_cards.card_uid = %s AND nfc_cards.status = 'active'
    """, (card_uid,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        pin = generate_pin()
        session['user_id'] = user[0]
        session['pin'] = pin
        email_body = f"Your login PIN is: {pin}"
        send_email(user[3], "Your Login PIN", email_body)  # user[3] is the email
        return redirect(url_for('enter_pin'))
    else:
        return jsonify({'status': 'error', 'message': 'User not found'})

# Route pour entrer le code PIN
@app.route('/enter_pin', methods=['GET', 'POST'])
def enter_pin():
    if request.method == 'POST':
        entered_pin = request.form.get('pin')
        if entered_pin == session.get('pin'):
            return redirect(url_for('profile'))
        else:
            return jsonify({'status': 'error', 'message': 'Invalid PIN'})

    return render_template('enter_pin.html')

# Route pour afficher les informations de l'utilisateur
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, first_name, last_name, email, service, created_at FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('profile.html', user=user)

# Page de connexion
@app.route('/login_page')
def login_page():
    return render_template('login.html')

# Page d'accueil simple pour confirmer que le serveur fonctionne
@app.route('/')
def home():
    return "Bienvenue sur l'API NFC!"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
