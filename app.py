import os
import random
import string
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message

app = Flask(__name__)

# ==================== CONFIGURATION ====================
# Flask-Mail Configuration (loaded securely from Render environment variables)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'defaultsecret')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

mail = Mail(app)

# ==================== MODELS ====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    unique_token = db.Column(db.String(100), unique=True, nullable=False)

# Create all tables inside application context
with app.app_context():
    db.create_all()

# ==================== ROUTES ====================
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for('register'))

        new_user = User(username=username, password=password, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username, password=password).first()

    if user:
        otp_code = str(random.randint(100000, 999999))
        unique_token = str(uuid.uuid4())

        new_otp = OTP(user_id=user.id, otp_code=otp_code, unique_token=unique_token)
        db.session.add(new_otp)
        db.session.commit()

        verify_link = url_for('verify_link', token=unique_token, _external=True)

        msg = Message("Your Unique OTP Verification",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[user.email])
        msg.body = f"""
Hello {user.username},

Your One-Time Password (OTP) is: {otp_code}

Alternatively, click this link to verify directly:
{verify_link}

If you did not request this, please ignore this email.

Best Regards,
Cloud MFA Security System
"""
        mail.send(msg)

        session['user_id'] = user.id
        flash("A verification email has been sent to your address.", "info")
        return redirect(url_for('verify'))

    flash("Invalid username or password!", "danger")
    return redirect(url_for('home'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp_code = request.form['otp']
        user_id = session.get('user_id')
        otp = OTP.query.filter_by(user_id=user_id, otp_code=otp_code).first()

        if otp:
            OTP.query.filter_by(user_id=user_id).delete()
            db.session.commit()
            flash("Login successful via OTP!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP!", "danger")
            return redirect(url_for('verify'))

    return render_template('verify.html')

@app.route('/verify/<token>')
def verify_link(token):
    otp = OTP.query.filter_by(unique_token=token).first()
    if otp:
        session['user_id'] = otp.user_id
        OTP.query.filter_by(user_id=otp.user_id).delete()
        db.session.commit()
        flash("Verification successful via email link!", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('home'))
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
