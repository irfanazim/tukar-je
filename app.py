from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])  
def login():
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])  
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return redirect(url_for('reset_password', token='dummy-token'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])  
def reset_password(token):
    return render_template('reset_password.html')

@app.route('/register', methods=['GET', 'POST'])  
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)