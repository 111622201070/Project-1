from flask import Flask, render_template, request, flash, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure secret key

DATABASE = 'users.db'
sender_email = "techarmycustomercare@gmail.com"
sender_password = "luavowqnvzhoofov"  # Replace with your 16-character App Password

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                mobile TEXT NOT NULL,
                password TEXT NOT NULL,
                otp TEXT
            )
        ''')
        conn.commit()
        conn.close()

init_db()

# Simple symptom-to-output mapping (replace with a real medical database/API in production)
def get_health_outputs(symptoms):
    symptom_map = {
        "fever": {
            "disease": "Common Cold or Flu",
            "medicines": "Paracetamol, Ibuprofen",
            "diet_plan": "Stay hydrated, consume warm fluids like soup, avoid cold foods"
        },
        "stomach pain": {
            "disease": "Gastritis or IBS",
            "medicines": "Antacids, Buscopan",
            "diet_plan": "Eat bland foods like rice and bananas, avoid spicy or fatty foods"
        },
        "headache": {
            "disease": "Tension Headache or Migraine",
            "medicines": "Aspirin, Sumatriptan",
            "diet_plan": "Stay hydrated, limit caffeine, eat magnesium-rich foods like nuts"
        }
    }
    # Default response if symptom not found
    symptoms_lower = symptoms.lower()
    for key in symptom_map:
        if key in symptoms_lower:
            return symptom_map[key]
    return {
        "disease": "Unknown (consult a doctor)",
        "medicines": "Consult a healthcare provider",
        "diet_plan": "Maintain a balanced diet and consult a professional"
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email.', 'error')
            return render_template('reset_password.html')

        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            conn.execute('UPDATE users SET otp = ? WHERE email = ?', (otp, email))
            conn.commit()

            subject = "Password Reset OTP"
            body = f"Your OTP for password reset is: {otp}\n\nPlease use this OTP to reset your password. It is valid for 10 minutes."
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = sender_email
            msg['To'] = email
            try:
                with smtplib.SMTP('smtp.gmail.com', 587) as server:
                    server.starttls()
                    server.login(sender_email, sender_password)
                    server.send_message(msg)
                flash('OTP sent to your email. Please check your inbox.', 'success')
            except Exception as e:
                flash(f'Failed to send OTP: {e}', 'error')
        else:
            flash('Email not found.', 'error')
        conn.close()
        return redirect(url_for('verify_otp', email=email))
    return render_template('reset_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if not email:
        flash('Invalid request.', 'error')
        return redirect(url_for('reset_password'))
    
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        verify_password = request.form.get('verify_password')

        if not all([entered_otp, new_password, verify_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('verify_otp.html', email=email)
        if new_password != verify_password:
            flash('Passwords do not match.', 'error')
            return render_template('verify_otp.html', email=email)

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and user['otp'] == entered_otp:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            conn.execute('UPDATE users SET password = ?, otp = NULL WHERE email = ?', 
                        (hashed_password, email))
            conn.commit()
            flash('Password reset successfully! Please log in.', 'success')
            conn.close()
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            conn.close()
            return render_template('verify_otp.html', email=email)
    return render_template('verify_otp.html', email=email)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        verify_password = request.form.get('verify_password')
        if not all([email, mobile, password, verify_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('register.html')
        if password != verify_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (email, mobile, password) VALUES (?, ?, ?)',
                         (email, mobile, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
        except sqlite3.IntegrityError:
            flash('Email already exists. Please use a different email.', 'error')
        finally:
            conn.close()
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('login.html', show_search=False)
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['user_email'] = email
            flash('Login successful!', 'success')
            return render_template('login.html', show_search=True)
        else:
            flash('Invalid email or password.', 'error')
            return render_template('login.html', show_search=False)
    return render_template('login.html', show_search=False)

@app.route('/search', methods=['POST'])
def search():
    if not session.get('logged_in'):
        flash('Please log in to use the search feature.', 'error')
        return redirect(url_for('login'))
    
    symptoms = request.form.get('symptoms')
    if not symptoms:
        flash('Please enter symptoms to search.', 'error')
        return render_template('login.html', show_search=True)
    
    outputs = get_health_outputs(symptoms)
    return render_template('login.html', show_search=True, symptoms=symptoms, outputs=outputs)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
