from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.secret_key = "a0e@ggNTH^%$#J"

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# CONFIGURE FLASK LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("You are already registered with that email! Log in instead.")
            return redirect(url_for('login'))

        new_user = User(
            email=email,
            password=generate_password_hash(request.form.get("password"), "pbkdf2:sha256", 8),
            name=request.form.get("name")
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        result = db.session.execute(db.select(User).where(User.email == request.form.get("email")))
        user = result.scalar()
        db.session.commit()
        if user:
            if check_password_hash(user.password, request.form.get("password")):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash("Incorrect Password.")
                return render_template("login.html")
        else:
            flash("User Not found")
            return render_template("login.html")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html", name=name, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory="static",path="files/file.pdf")


if __name__ == "__main__":
    app.run(debug=True)
