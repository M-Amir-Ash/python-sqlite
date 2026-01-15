from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functools import wraps
import os

app = Flask(__name__)

# =========================================================
# B.1 & B.3 - Authentication & Secure Credential Management
# =========================================================

# Secure secret key (avoid hard-coded secrets)
app.config['SECRET_KEY'] = os.environ.get(
    'FLASK_SECRET_KEY', 'change-this-secret-key'
)

# Credentials loaded from environment variables
VALID_USERNAME = os.environ.get('APP_USERNAME', 'admin')
VALID_PASSWORD = os.environ.get('APP_PASSWORD', 'password123')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =========================================================
# Authentication Decorator (CWE-306)
# =========================================================
def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get('user'):
            flash('Please log in to access this function.', 'warning')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped_view

# =========================================================
# Database Model
# =========================================================
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)

# =========================================================
# Routes
# =========================================================
@app.route('/')
def index():
    students = db.session.execute(
        text('SELECT * FROM student')
    ).fetchall()
    return render_template('index.html', students=students)

# -------------------------
# Login & Logout
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session['user'] = username
            flash('Login successful.', 'success')
            return redirect(url_for('index'))

        flash('Invalid credentials.', 'danger')

    return '''
    <h2>Login</h2>
    <form method="post">
        <label>Username:
            <input type="text" name="username">
        </label><br>
        <label>Password:
            <input type="password" name="password">
        </label><br>
        <button type="submit">Login</button>
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

# =========================================================
# B.4 - SQL Injection Mitigation (CWE-89)
# =========================================================
@app.route('/add', methods=['POST'])
@login_required
def add_student():
    name = request.form['name']
    age = request.form['age']
    grade = request.form['grade']

    db.session.execute(
        text(
            "INSERT INTO student (name, age, grade) "
            "VALUES (:name, :age, :grade)"
        ),
        {'name': name, 'age': age, 'grade': grade}
    )
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
@login_required
def delete_student(id):
    db.session.execute(
        text("DELETE FROM student WHERE id = :id"),
        {'id': id}
    )
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        grade = request.form['grade']

        db.session.execute(
            text(
                "UPDATE student "
                "SET name = :name, age = :age, grade = :grade "
                "WHERE id = :id"
            ),
            {
                'name': name,
                'age': age,
                'grade': grade,
                'id': id
            }
        )
        db.session.commit()
        return redirect(url_for('index'))

    student = db.session.execute(
        text("SELECT * FROM student WHERE id = :id"),
        {'id': id}
    ).fetchone()

    return render_template('edit.html', student=student)

# =========================================================
# Application Entry Point
# =========================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
