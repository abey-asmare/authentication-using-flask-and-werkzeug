from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager(app)
db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# Line below only required once, when creating DB.
# db.create_all()

def authenticate_user(user, email, password) ->bool :
    if user:
        if user.email == email and check_password_hash(user.password, password):
            print("correct")
            return True
        else:
            print("try again")
            return False
    print("doesn't exist")
    return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register/', methods = ["POST", "GET"])
def register():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password =  request.form.get('password')
        user_found = User.query.filter_by(email = email).first()
        if not user_found:
            new_user = User(
               name = name ,
               email = email,
               password = generate_password_hash(password=password, method= 'pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
        else:
            flash("credential exist!")
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/login', methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email = email).first()
        if authenticate_user(user=user, email=email, password=password):
            login_user(user=user)
            flash("You were successfully logged in")
            return redirect(url_for('secrets'))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
