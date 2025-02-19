# app.py - 主程序文件
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_moment import Moment
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
import logging, time
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length
import uuid
import os
from datetime import datetime

CONTENT_LENGTH_MB = 64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{0}:{1}@localhost/clipboard_db'.format(
    os.environ['SQL_USERNAME'], os.environ['SQL_PASSWORD']
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = CONTENT_LENGTH_MB * 1024 * 1024

limiter = Limiter(
    app=app,
    key_func=lambda: current_user.id if current_user.is_authenticated else get_remote_address(),
    default_limits=["10 per second"]
)

csrf = CSRFProtect(app)

moment = Moment(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "请先登录以访问该页面。"

migrate = Migrate(app, db)

SYSTEM_USER = 11

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
logFormatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logFile = logging.FileHandler("log/{0}.log".format(time.strftime("%Y-%m-%d_%H-%M-%S",time.localtime(time.time()))), encoding="utf-8")
logFile.setLevel(logging.DEBUG)
logFile.setFormatter(logFormatter)
logger.addHandler(logFile)

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(60))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 添加created_at字段
    clipboards = db.relationship('Clipboard', backref='owner', lazy=True)
    mode = db.Column(db.String(10), default='blacklist')  # 模式：blacklist 或 whitelist
    blacklist = db.Column(db.Text, default='')  # 黑名单用户ID列表，用逗号分隔
    whitelist = db.Column(db.Text, default='')  # 白名单用户ID列表，用逗号分隔
    notifications = db.relationship('Notification', backref='user', lazy="dynamic")  # 通知

class Clipboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(36), unique=True)
    content = db.Column(db.Text(16777215))
    # db.Text(4294967295)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    note = db.Column(db.Text, default='')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    is_public = BooleanField('公开剪贴板', default=True)

class ProfileForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(max=50)])
    current_password = PasswordField('当前密码（仅修改密码时需要）')
    new_password = PasswordField('新密码')
    confirm_password = PasswordField('确认新密码')
    mode = SelectField('模式', choices=[('blacklist', '黑名单模式'), ('whitelist', '白名单模式')])
    blacklist = StringField('黑名单用户（用户名，用逗号分隔）')
    whitelist = StringField('白名单用户（用户名，用逗号分隔）')

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
    clipboards = Clipboard.query.filter_by(user_id=current_user.id).order_by(Clipboard.created_at.desc()).all()
    return render_template('dashboard.html', clipboards=clipboards, system=False, user_name="我", user_id=current_user.id)

@app.route('/dashboard/system')
@login_required
def dashboard_system():
    if not current_user.is_admin:
        abort(403)
    clipboards = Clipboard.query.filter_by(user_id=SYSTEM_USER).order_by(Clipboard.created_at.desc()).all()
    return render_template('dashboard.html', clipboards=clipboards, system=True, user_name="", user_id=SYSTEM_USER)

@app.route('/dashboard/<int:user_id>')
@login_required
def dashboard_user(user_id):
    if user_id == current_user.id:
        return redirect(url_for('dashboard'))
    if user_id == SYSTEM_USER:
        return redirect(url_for('dashboard_system'))
    if not current_user.is_admin:
        abort(403)
    if user_id == SYSTEM_USER:
        return redirect(url_for('dashboard_system'))
    clipboards = Clipboard.query.filter_by(user_id=user_id).order_by(Clipboard.created_at.desc()).all()
    return render_template('dashboard.html', clipboards=clipboards, system=False, user_name=User.query.get(user_id).username, user_id=user_id)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.id == SYSTEM_USER:
            flash('系统用户无法登录', 'danger')
            return redirect(url_for('login'))
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if next_page:
                if "logout" in next_page:
                    next_page = ""
            logger.info('User {} logged in'.format(user.username))
            return redirect(next_page or url_for('dashboard'))
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
        notification = Notification(
            user_id=user.id,
            message=f'欢迎使用剪贴板，请阅读 “System: 新用户必读”，可直接在上方跳转栏输入“System: 新用户必读”查看。'
        )
        db.session.add(notification)
        db.session.commit()
        logger.info("User {} registered".format(user.username))
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logger.info('User {} logged out'.format(current_user.username))
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
            user_id=current_user.id,
            is_public=form.is_public.data
        )
        new_clip.note = request.form.get('note', '').strip()
        if new_clip.note == "None":
            new_clip.note = ""
        # 管理员可以修改 UID
        if current_user.is_admin:
            new_uid = request.form.get('uid')
            if new_uid and new_uid != new_clip.uid:
                # 检查新 UID 是否已存在
                if new_clip.query.filter_by(uid=new_uid).first():
                    flash('该 UID 已存在，请使用其他 UID', 'danger')
                else:
                    new_clip.uid = new_uid
        db.session.add(new_clip)
        db.session.commit()
        logger.info('User {} created clipboard {}'.format(current_user.username, new_clip.uid))
        return redirect(url_for('view_clip', uid=new_clip.uid))
    return render_template('edit.html', form=form, clipboard=form)

@app.route('/create/system', methods=['GET', 'POST'])
@login_required
def create_system():
    if not current_user.is_admin:
        abort(403)
    form = ClipboardForm()
    if form.validate_on_submit():
        new_clip = Clipboard(
            uid=str(uuid.uuid4()),
            content=form.content.data,
            user_id=SYSTEM_USER,
            is_public=form.is_public.data
        )
        new_clip.note = request.form.get('note', '').strip()
        if new_clip.note == "None":
            new_clip.note = ""
        # 管理员可以修改 UID
        if current_user.is_admin:
            new_uid = request.form.get('uid')
            if new_uid and new_uid != new_clip.uid:
                # 检查新 UID 是否已存在
                if new_clip.query.filter_by(uid=new_uid).first():
                    flash('该 UID 已存在，请使用其他 UID', 'danger')
                else:
                    new_clip.uid = new_uid
        db.session.add(new_clip)
        db.session.commit()
        logger.info('User {} created clipboard {} for system'.format(current_user.username, new_clip.uid))
        return redirect(url_for('view_clip', uid=new_clip.uid))
    return render_template('edit.html', form=form, clipboard=form)

@app.route('/create/<int:user_id>', methods=['GET', 'POST'])
@login_required
def create_user(user_id):
    if user_id == current_user.id:
        return redirect(url_for("create"))
    if user_id == SYSTEM_USER:
        return redirect(url_for("create_system"))
    if not current_user.is_admin:
        abort(403)
    form = ClipboardForm()
    if form.validate_on_submit():
        new_clip = Clipboard(
            uid=str(uuid.uuid4()),
            content=form.content.data,
            user_id=user_id,
            is_public=form.is_public.data
        )
        new_clip.note = request.form.get('note', '').strip()
        if new_clip.note == "None":
            new_clip.note = ""
        # 管理员可以修改 UID
        if current_user.is_admin:
            new_uid = request.form.get('uid')
            if new_uid and new_uid != new_clip.uid:
                # 检查新 UID 是否已存在
                if new_clip.query.filter_by(uid=new_uid).first():
                    flash('该 UID 已存在，请使用其他 UID', 'danger')
                else:
                    new_clip.uid = new_uid
        db.session.add(new_clip)
        db.session.commit()
        logger.info('User {} created clipboard {} for {}'.format(current_user.username, new_clip.uid, User.query.get(user_id).username))
        return redirect(url_for('view_clip', uid=new_clip.uid))
    return render_template('edit.html', form=form, clipboard=form)

@app.route('/edit/<uid>', methods=['GET', 'POST'])
@login_required
def edit(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    if current_user.id != clipboard.user_id and not current_user.is_admin:
        abort(403)

    form = ClipboardForm(obj=clipboard)
    if form.validate_on_submit():
        # 更新内容
        clipboard.content = form.content.data
        clipboard.is_public = form.is_public.data
        
        # 更新备注
        clipboard.note = request.form.get('note', '').strip()
        if clipboard.note == "None":
            clipboard.note = ""
        
        # 管理员可以修改 UID
        if current_user.is_admin:
            new_uid = request.form.get('uid')
            if new_uid == "":
                new_uid = str(uuid.uuid4())
            if new_uid and new_uid != clipboard.uid:
                # 检查新 UID 是否已存在
                if Clipboard.query.filter_by(uid=new_uid).first():
                    flash('该 UID 已存在，请使用其他 UID', 'danger')
                    return redirect(url_for('edit', uid=clipboard.uid))
                clipboard.uid = new_uid
        db.session.commit()
        flash('剪贴板已更新', 'success')
        logger.info('User {} edited clipboard {}'.format(current_user.username, clipboard.uid))
        return redirect(url_for('view_clip', uid=clipboard.uid))
    return render_template('edit.html', form=form, clipboard=clipboard)

@app.route('/delete/<uid>', methods=['GET', 'POST'])
@login_required
def delete(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    if current_user.id != clipboard.user_id and not current_user.is_admin:
        abort(403)
    logger.info('User {} deleted clipboard {}'.format(current_user.username, clipboard.uid))
    db.session.delete(clipboard)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_notification/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_notification(id):
    notification = Notification.query.filter_by(id=id).first_or_404()
    if not current_user.is_admin:
        abort(403)
    logger.info('User {} deleted notification {}'.format(current_user.username, notification.id))
    db.session.delete(notification)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/clip/<uid>', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def view_clip(uid):
    clipboard = Clipboard.query.filter_by(uid=uid).first_or_404()
    
    # 权限检查
    if not clipboard.is_public and \
       (not current_user.is_authenticated or 
        (current_user.id != clipboard.user_id and not current_user.is_admin)):
        abort(403)
    
    # 处理邀请
    if request.method == 'POST' and (current_user.id == clipboard.user_id or current_user.is_admin):
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            # 检查用户是否在黑名单或白名单中
            if user.mode == 'blacklist' and str(current_user.id) in user.blacklist.split(','):
                flash(f'{username} 已将你加入黑名单，无法邀请', 'danger')
            elif user.mode == 'whitelist' and str(current_user.id) not in user.whitelist.split(','):
                flash(f'{username} 未将你加入白名单，无法邀请', 'danger')
            else:
                # 创建通知
                notification = Notification(
                    user_id=user.id,
                    message=f'你被邀请查看剪贴板：{clipboard.uid}'
                )
                db.session.add(notification)
                db.session.commit()
                logger.info('User {} invited {} to view clipboard {}'.format(current_user.username, username, clipboard.uid))
                flash(f'已成功邀请 {username}', 'success')
        else:
            flash('用户不存在', 'danger')
    
    return render_template('view.html', 
                         clipboard=clipboard,
                         is_owner=current_user.is_authenticated and 
                                  (current_user.id == clipboard.user_id or 
                                   current_user.is_admin))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    clipboards = Clipboard.query.all()
    users = User.query.all()
    notifications = Notification.query.all()
    return render_template('admin.html', clipboards=clipboards, users=users, notifications=notifications, SYSTEM_USER=SYSTEM_USER)

@app.route('/set_admin/<int:user_id>', methods=['POST'])
@login_required
def set_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'已成功将 {user.username} 设为管理员', 'success')
    logger.info('User {} set {} as admin'.format(current_user.username, user.username))
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
        
        # 更新模式
        current_user.mode = form.mode.data
        
        # 更新黑名单
        blacklist_usernames = [name.strip() for name in form.blacklist.data.split(',')]
        blacklist_ids = []
        for username in blacklist_usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                blacklist_ids.append(str(user.id))
        current_user.blacklist = ','.join(blacklist_ids)
        
        # 更新白名单
        whitelist_usernames = [name.strip() for name in form.whitelist.data.split(',')]
        whitelist_ids = []
        for username in whitelist_usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                whitelist_ids.append(str(user.id))
        current_user.whitelist = ','.join(whitelist_ids)
        
        db.session.commit()
        flash('资料更新成功', 'success')
        logger.info('User {} updated profile'.format(current_user.username))
        return redirect(url_for('dashboard'))
    
    # 初始化表单数据
    form.mode.data = current_user.mode
    form.blacklist.data = ', '.join([User.query.get(int(id)).username for id in current_user.blacklist.split(',') if id])
    form.whitelist.data = ', '.join([User.query.get(int(id)).username for id in current_user.whitelist.split(',') if id])
    
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
    Notification.query.filter_by(user_id=user_id).delete()
    # 删除用户
    logger.info('User {} deleted user {}'.format(current_user.username, target_user.username))
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
    
    logger.info('User {} toggled admin status of {}'.format(current_user.username, user.username))
    return redirect(url_for('admin'))

@app.route('/delete_all_clipboards', methods=['POST'])
@login_required
def delete_all_clipboards():
    if not current_user.is_admin:
        abort(403)
    
    try:
        num_deleted = Clipboard.query.filter(Clipboard.user_id != SYSTEM_USER).delete()
        db.session.commit()
        flash(f'已删除全部 {num_deleted} 个剪贴板', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除失败: ' + str(e), 'danger')
        logger.error('Failed to delete all clipboards: ' + str(e))
    
    logger.info('User {} deleted all clipboards'.format(current_user.username))
    return redirect(url_for('admin'))

@app.route('/delete_all_readed_notifications', methods=['POST'])
@login_required
def delete_all_readed_notifications():
    if not current_user.is_admin:
        abort(403)
    
    try:
        num_deleted = Notification.query.filter(Notification.is_read).delete()
        db.session.commit()
        flash(f'已删除全部 {num_deleted} 个已读通知', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除失败: ' + str(e), 'danger')
        logger.error('Failed to delete all readed notifications: ' + str(e))
    
    logger.info('User {} deleted all readed notifications'.format(current_user.username))
    return redirect(url_for('admin'))

@app.route('/delete_all_notifications', methods=['POST'])
@login_required
def delete_all_notifications():
    if not current_user.is_admin:
        abort(403)
    
    try:
        num_deleted = Notification.query.delete()
        db.session.commit()
        flash(f'已删除全部 {num_deleted} 个通知', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除失败: ' + str(e), 'danger')
        logger.error('Failed to delete all notifications: ' + str(e))
    
    logger.info('User {} deleted all notifications'.format(current_user.username))
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
        
        # 更新模式
        target_user.mode = form.mode.data
        
        # 更新黑名单
        blacklist_usernames = [name.strip() for name in form.blacklist.data.split(',')]
        blacklist_ids = []
        for username in blacklist_usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                blacklist_ids.append(str(user.id))
        target_user.blacklist = ','.join(blacklist_ids)
        
        # 更新白名单
        whitelist_usernames = [name.strip() for name in form.whitelist.data.split(',')]
        whitelist_ids = []
        for username in whitelist_usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                whitelist_ids.append(str(user.id))
        target_user.whitelist = ','.join(whitelist_ids)
        
        db.session.commit()
        flash('用户信息已更新', 'success')
        logger.info('User {} updated user {}'.format(current_user.username, target_user.username))
        return redirect(url_for('admin'))
    
    # 初始化表单数据
    form.mode.data = target_user.mode
    form.blacklist.data = ', '.join([User.query.get(int(id)).username for id in target_user.blacklist.split(',') if id])
    form.whitelist.data = ', '.join([User.query.get(int(id)).username for id in target_user.whitelist.split(',') if id])
    
    return render_template('edit_user.html', form=form, target_user=target_user)

@app.route('/notifications')
@login_required
def notifications():
    # 标记所有通知为已读
    for notification in current_user.notifications:
        notification.is_read = True
    db.session.commit()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications, user_id=current_user.id, tag="")

@app.route('/notifications/<int:user_id>')
@login_required
def get_notifications(user_id):
    if not current_user.is_admin and current_user.id != user_id:
        abort(403)
    if user_id == current_user.id:
        return redirect(url_for('notifications'))
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications, user_id=user_id, tag="{0}的".format(User.query.get(user_id).username))

@app.route('/send_notification/<int:user_id>', methods=['POST'])
@login_required
def send_notification(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    message = request.form.get('message')
    if message:
        notification = Notification(
            user_id=user.id,
            message=message
        )
        db.session.add(notification)
        db.session.commit()
        flash(f'已成功发送通知给 {user.username}', 'success')
        logger.info('User {} sent notification to {}'.format(current_user.username, user.username))
    else:
        flash('通知内容不能为空', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/send_global_notification', methods=['POST'])
@login_required
def send_global_notification():
    if not current_user.is_admin:
        abort(403)
    
    message = request.form.get('message')
    if message:
        users = User.query.all()
        for user in users:
            notification = Notification(
                user_id=user.id,
                message=message
            )
            db.session.add(notification)
        db.session.commit()
        flash('已成功发送全局通知', 'success')
        logger.info('User {} sent global notification'.format(current_user.username))
    else:
        flash('通知内容不能为空', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/clear_notifications/<int:user_id>', methods=['POST'])
@login_required
def clear_notifications(user_id):
    if not current_user.is_admin and current_user.id != user_id:
        abort(403)
    # 删除当前用户的所有通知
    Notification.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    flash('所有通知已清空', 'success')
    logger.info('User {} cleared notifications of user {}'.format(current_user.username, User.query.get(user_id).username))
    return redirect(url_for('get_notifications', user_id=user_id))

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('rate_limit.html', 
                         message="请求过于频繁，请稍后再试"), 429

@app.errorhandler(400)
def bad_request(e):
    return render_template('rate_limit.html', 
                         message="请求无效"), 400

@app.errorhandler(403)
def error403(e):
    return render_template('rate_limit.html', 
                         message="你无法访问此页面"), 403

@app.errorhandler(404)
def error404(e):
    return render_template('rate_limit.html', 
                         message="你所访问的页面不存在或已隐藏"), 404

@app.errorhandler(413)
def error413(e):
    return render_template('rate_limit.html', 
                         message="发送的数据包过大"), 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
