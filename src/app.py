# app.py - 主程序文件
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length
import uuid
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:65399306@localhost/clipboard_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(60))
    is_admin = db.Column(db.Boolean, default=False)
    clipboards = db.relationship('Clipboard', backref='owner', lazy=True)

class Clipboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(36), unique=True)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# 表单类
class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])

class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('密码', validators=[DataRequired()])

class ClipboardForm(FlaskForm):
    content = TextAreaField('内容', validators=[DataRequired()])

# 登录管理
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 路由
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    clipboards = Clipboard.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', clipboards=clipboards)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('无效的用户名或密码')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ClipboardForm()
    if form.validate_on_submit():
        new_clip = Clipboard(
            uid=str(uuid.uuid4()),
            content=form.content.data,
            user_id=current_user.id
        )
        db.session.add(new_clip)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('edit.html', form=form)

@app.route('/edit/<uid>', methods=['GET', 'POST'])
@login_required
def edit(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    if clipboard.owner != current_user and not current_user.is_admin:
        abort(403)
    form = ClipboardForm(obj=clipboard)
    if form.validate_on_submit():
        clipboard.content = form.content.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('edit.html', form=form)

@app.route('/delete/<uid>')
@login_required
def delete(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    if clipboard.owner != current_user and not current_user.is_admin:
        abort(403)
    db.session.delete(clipboard)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/clip/<uid>')
def view_clip(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    return render_template('view.html', clipboard=clipboard)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    clipboards = Clipboard.query.all()
    users = User.query.all()
    return render_template('admin.html', clipboards=clipboards, users=users)

if __name__ == '__main__':
    app.run(debug=True)