from flask import Flask, render_template, request, session, redirect, url_for
import mysql.connector
import random
import string
import secrets
import bcrypt

def generate_secret_key():
    return secrets.token_hex(16)

# Generate a random CAPTCHA string
def generate_captcha(n):
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=n))
    return captcha

app = Flask(__name__)
app.secret_key = generate_secret_key()

# Create MySQL connection
conn = mysql.connector.connect(host='localhost', user='root', password='9579', database='newreggg')
cursor = conn.cursor()

# Route for login page
@app.route('/')
def index():
    session['captcha'] = generate_captcha(6)  # Generate CAPTCHA and store in session
    return render_template('login.html', captcha=session['captcha'])

# Route for login authentication
@app.route('/login', methods=['POST'])
# Route for login authentication
@app.route('/login', methods=['POST'])
# Route for login authentication
@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            entered_captcha = request.form['captcha'].upper()  # Get entered CAPTCHA string and convert to uppercase

            # Verify CAPTCHA
            if entered_captcha != session.get('captcha').upper():
                return 'CAPTCHA does not match. Please try again.'

            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user:
                # Check if the entered password matches the stored hashed password
                if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                    session['user_id'] = user[0]  # Set the user_id session variable
                    session.pop('captcha', None)
                    return redirect(url_for('secured_area'))
                else:
                    return 'Invalid password.'
            else:
                return 'User not found. Please check your email.'

        except Exception as e:
            return f'Login failed: {str(e)}'

# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            fullname = request.form['fullname']
            email = request.form['email']
            password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())

            cursor.execute("INSERT INTO users (Fullname, email, password) VALUES (%s, %s, %s)",
                           (fullname, email, password.decode('utf-8')))
            conn.commit()

            return redirect(url_for('index'))  # Redirect to login page after successful registration
        except Exception as e:
            return f'Registration failed: {str(e)}'
    else:
        # If it's a GET request, render the registration form
        return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/secured_area')
def secured_area():
    if 'user_id' in session:
        return render_template('bonvoyage.html')
    else:
        return redirect(url_for('index'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

if __name__ == '__main__':
    app.run(debug=True)
