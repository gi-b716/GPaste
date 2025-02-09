# app.py - 主程序文件
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length
import uuid
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:65399306@localhost/clipboard_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

limiter = Limiter(
    app=app,
    key_func=lambda: current_user.id if current_user.is_authenticated else get_remote_address(),
    default_limits=["10 per second"]
)

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "请先登录以访问该页面。"

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(60))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 添加created_at字段
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
    confirm_password = PasswordField('确认密码', validators=[DataRequired()])

class ClipboardForm(FlaskForm):
    content = TextAreaField('内容', validators=[DataRequired()])

class ProfileForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(max=50)])
    current_password = PasswordField('当前密码（仅修改密码时需要）')
    new_password = PasswordField('新密码')
    confirm_password = PasswordField('确认新密码')

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
@limiter.limit("60 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('无效的用户名或密码', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        if form.password.data != form.confirm_password.data:
            flash('密码不一致', 'danger')
            return redirect(url_for('register'))
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录', 'success')
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
@limiter.limit("30 per minute")
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

@app.route('/set_admin/<int:user_id>', methods=['POST'])
@login_required
def set_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'已成功将 {user.username} 设为管理员', 'success')
    return redirect(url_for('admin'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        # 修改用户名
        if form.username.data != current_user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('用户名已存在', 'danger')
                return redirect(url_for('profile'))
            current_user.username = form.username.data
        
        # 修改密码
        if form.new_password.data:
            if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
                flash('当前密码错误', 'danger')
                return redirect(url_for('profile'))
            if form.new_password.data != form.confirm_password.data:
                flash('新密码不一致', 'danger')
                return redirect(url_for('profile'))
            current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        
        db.session.commit()
        flash('资料更新成功', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('profile.html', form=form)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    target_user = User.query.get_or_404(user_id)
    # 权限验证
    if not (current_user.is_admin or current_user.id == user_id):
        abort(403)
    # 删除关联剪贴板
    Clipboard.query.filter_by(user_id=user_id).delete()
    # 删除用户
    db.session.delete(target_user)
    db.session.commit()
    if current_user.id == user_id:
        logout_user()
        flash('账户已删除', 'success')
        return redirect(url_for('login'))
    else:
        flash('用户已删除', 'success')
        return redirect(url_for('admin'))

@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('不能修改自己的管理员状态', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f'已{"取消" if not user.is_admin else "设置"} {user.username} 的管理员权限', 'success')
    
    return redirect(url_for('admin'))

@app.route('/delete_all_clipboards', methods=['POST'])
@login_required
def delete_all_clipboards():
    if not current_user.is_admin:
        abort(403)
    
    try:
        num_deleted = Clipboard.query.delete()
        db.session.commit()
        flash(f'已删除全部 {num_deleted} 个剪贴板', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除失败: ' + str(e), 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    target_user = User.query.get_or_404(user_id)
    form = ProfileForm(obj=target_user)
    
    if form.validate_on_submit():
        # 管理员无需验证原密码
        if form.username.data != target_user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('用户名已存在', 'danger')
                return redirect(url_for('edit_user', user_id=user_id))
            target_user.username = form.username.data
        
        if form.new_password.data:
            if form.new_password.data != form.confirm_password.data:
                flash('新密码不一致', 'danger')
                return redirect(url_for('edit_user', user_id=user_id))
            target_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        
        db.session.commit()
        flash('用户信息已更新', 'success')
        return redirect(url_for('admin'))
    
    return render_template('edit_user.html', form=form, target_user=target_user)

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('rate_limit.html', 
                         message="请求过于频繁，请稍后再试"), 429

if __name__ == '__main__':
    app.run(debug=True)