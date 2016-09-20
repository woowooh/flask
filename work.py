from flask import Flask, render_template,url_for,redirect,\
flash, current_app,request, abort, make_response
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.moment import Moment
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from flask.ext.script import Manager, Shell
from flask.ext.login import LoginManager, login_user,UserMixin,\
logout_user, login_required, current_user, AnonymousUserMixin
from flask.ext.pagedown.fields import PageDownField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo,ValidationError
from werkzeug.security import  generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from wtforms import StringField, SubmitField, PasswordField,\
BooleanField, SelectField, TextAreaField
from functools import wraps
import os
import random
from flask.ext.pagedown import PageDown
from markdown import markdown
import bleach

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
moment = Moment(app)
bootstrap = Bootstrap(app)
manager = Manager(app)
pagedown = PageDown(app)

app.config['FLASKY_COMMENTS_PER_PAGE'] = 20
app.config['FLASKY_FOLLOWERS_PER_PAGE']= 20
app.config['FLASKY_POSTS_PER_PAGE'] = 20
app.config['SECRET_KEY'] = 'hard to guess'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = \
	'sqlite:///' + os.path.join(basedir, 'data.sqlite')

login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

db = SQLAlchemy(app) 

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

def make_shell_context():
	return dict(db=db, User=User, Role=Role, app=app)

manager.add_command('shell', Shell(make_context=make_shell_context))

class Permission:
	FOLLOW = 0x01
	COMMENT = 0x02
	WRITE_ARTICLES = 0x04
	MODERATE_COMMENTS = 0x08
	ADMINISTER = 0xff

class Follow(db.Model):
	__tablename__ = 'follows'
	followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True)
	follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Post(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	body = db.Column(db.Text)
	body_html = db.Column(db.Text)
	comments = db.relationship('Comment', backref='post', lazy='dynamic')

	@staticmethod
	def generate_fake(count=100):
		from random import seed, randint
		import forgery_py

		seed()
		user_count = User.query.count()
		for i in range(count):
			u = User.query.offset(randint(0, user_count - 1)).first()
			p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1,3)),
				timestamp=forgery_py.date.date(True),
				author=u)
			db.session.add(p)
			db.session.commit()

	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
						'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
						'h1', 'h2', 'h3','p']
		target.body_html = bleach.linkify(bleach.clean(
			markdown(value, output_format='html'),
			tags=allowed_tags, strip=True))

db.event.listen(Post.body, 'set', Post.on_changed_body)

class User(UserMixin,db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique =True, index=True)
	email = db.Column(db.String(64), unique=True, index=True)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	confirmed = db.Column(db.Boolean, default=False)
	password_hash = db.Column(db.String(128))
	name = db.Column(db.String(64))
	about_me = db.Column(db.Text())
	location = db.Column(db.String(64))
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
	posts = db.relationship('Post', backref='author', lazy='dynamic')
	comments = db.relationship('Comment', backref='author', lazy='dynamic')
	followed = db.relationship('Follow', 
								foreign_keys=[Follow.follower_id],
								backref=db.backref('follower', lazy='joined'),
								lazy='dynamic',
								cascade='all, delete-orphan')
	followers = db.relationship('Follow',
								foreign_keys=[Follow.followed_id],
								backref=db.backref('followed', lazy='joined'),
								lazy='dynamic',
								cascade='all, delete-orphan')

	def is_following(self, user):
		return self.followed.filter_by(
					followed_id=user.id).first() is not None

	def is_followed_by(self, user):
		return self.followers.filter_by(
					follower_id=user.id).first() is not None

	def follow(self, user):
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)

	def unfollow(self, user):
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			db.session.delete(f)


	@property
	def password(self):
		raise AttributeError('Password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def generate_confirmation_token(self, expiration= 3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirmation':self.id})

	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
		if data.get('confirmation') != self.id:
			return False
		self.confirmed = True
		db.session.add(self)
		return True

	def __repr__(self):
		return '<User %r>' % self.username

	def __init__(self, **kwargs):
		super(User,self).__init__(**kwargs)
		if self.role is None:
			if self.email == 'zaoshuizaoqi@ganshenme.com':
				self.role = Role.query.filter_by(permissions=0xff).first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()
		self.follow(self)


	def can(self, permissions):
		return self.role is not None and \
		(self.role.permissions & permissions) == permissions

	def is_administrator(self):
		return self.can(Permission.ADMINISTER)

	def ping(self):
		self.last_seen = datetime.utcnow()
		db.session.add(self)

	@staticmethod
	def generate_fake(count=100):
		from sqlalchemy.exc import IntegrityError
		from random import seed
		import forgery_py

		seed()
		for i in range(count):
			u = User(email=forgery_py.internet.email_address(),
					 username=forgery_py.internet.user_name(True),
					 password=forgery_py.lorem_ipsum.word(),
					 confirmed=True,
					 name=forgery_py.name.full_name(),
					 location=forgery_py.address.city(),
					 about_me=forgery_py.lorem_ipsum.sentence(),
					 member_since=forgery_py.date.date(True))
			db.session.add(u)
			try:
				db.session.commit()
			except IntegrityError:
				db.session.rollback()

	@staticmethod
	def add_self_follows():
		for user in User.query.all():
			if not user.is_following(user):
				user.follow(user)
				db.session.add(user)
				db.session.commit()

	@property
	def followed_posts(self):
		return Post.query.join(Follow,
			Follow.followed_id == Post.author_id)\
			.filter(Follow.follower_id == self.id)

class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False

	def is_administrator(self):
		return False

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text)
	body_html = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
	disabled = db.Column(db.Boolean)

	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
						'strong']
		target.body_html = bleach.linkify(bleach.clean(
			markdown(value, output_format='html'),
			tags=allowed_tags, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_changed_body)

login_manager.anonymous_user = AnonymousUser	


class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64))
	users = db.relationship('User', backref='role')
	default = db.Column(db.Boolean, default=False, index=True)
	permissions = db.Column(db.Integer)

	def __repr__(self):
		return '<Role %r>' % self.name

	@staticmethod
	def insert_roles():
		roles = {
			'User':(Permission.FOLLOW |
					Permission.COMMENT |
					Permission.WRITE_ARTICLES, True),
			'Moderator':(Permission.FOLLOW |
						 Permission.COMMENT |
						 Permission.WRITE_ARTICLES |
						 Permission.MODERATE_COMMENTS, False),
			'Administrator':(0xff,False)
		}
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			role.permissions = roles[r][0]
			role.default = roles[r][1]
			db.session.add(role)
		db.session.commit()

class LoginForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64),\
						 Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me login')
	SubmitField = SubmitField('Log In')

class RegistrationForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64),\
											 Email()])
	username = StringField('Username', validators=[Required(), Length(1, 64),\
					Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
						   'Username must have only letters,' 
						   'numbers, dots or underscores')])
	password = PasswordField('Password', validators=[Required(), EqualTo(
							'password2', message='Passwords must match.')])
	password2 = PasswordField('Confirm your password', validators=[Required()])
	submit = SubmitField('Register')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already exists')

class EditProfileForm(Form):
	name = StringField('Real name', validators=[Required(), Length(0,64)])
	location = StringField('Location', validators=[Required(), Length(0, 64)])
	about_me = TextAreaField('About_me')
	submit = SubmitField('Submit')			

class EditProfileAdminForm(Form):
	email = StringField('Email', validators=[Required(), Length(1,64),
											Email()])
	username = StringField('Username',validators=[Required(), Length(1,64),
							Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
								   'Username must have only letters, '
								   'numbers, dots or underscores')])
	confirmed = BooleanField('Confirmed')
	role = SelectField('Role', coerce=int)
	name = StringField('Real name', validators=[Length(0, 64)])
	location = StringField('Location', validators=[Length(0, 64)])
	about_me = TextAreaField('About me')
	submit = SubmitField('Submit')

	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm,self).__init__(*args, **kwargs)
		self.role.choices = [(role.id, role.name)
							for role in Role.query.order_by(Role.name).all()]
		self.user = user

	def validate_email(self, field):
		if field.data != self.user.email and \
		User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already exists')

	def validate_username(self, field):
		if field.data != self.user.username and \
		User.query.filter_by(username=username).first():
			raise ValidationError('Username already used')

class PostForm(Form):
	body = PageDownField("what's on your mind?", validators=[Required()])
	submit = SubmitField('Submit')

class CommentForm(Form):
	body = StringField('', validators=[Required()])
	submit = SubmitField('Submit')

@app.route('/login', methods=['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(url_for('index'))
		flash('Login Fail')
	return render_template('login.html', form=form, current_time=datetime.utcnow())

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logout')
	return redirect(url_for('index'))

@app.route('/',methods=['GET','POST'])
def index():
	form = PostForm()
	if form.validate_on_submit() and \
		current_user.can(Permission.WRITE_ARTICLES):
		post = Post(body=form.body.data,
				author=current_user._get_current_object())
		db.session.add(post)
		return redirect(url_for('index'))
	page = request.args.get('page', 1, int)
	show_followed = False
	if current_user.is_authenticated:
		show_followed = bool(request.cookies.get('show_followed', ''))
	if show_followed:
		query = current_user.followed_posts
	else:
		query = Post.query
	pagination = query.order_by(Post.timestamp.desc()).paginate(
		page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
		error_out=False)
	posts = pagination.items
	return render_template('index.html', form=form, posts=posts,
							show_followed=show_followed, pagination=pagination)

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user=User(email=form.email.data,
				  username=form.username.data,
				  password=form.password.data)
		db.session.add(user)
		flash('You can now log in')
		return redirect(url_for('login'))
	return render_template('register.html', form=form)

@app.route('/reset-password-request', methods=['GET','POST'])
def reset_password_request():
	pass

@app.route('/changepwd', methods=['GET', 'POST'])
def changepwd():
	pass

def permission_required(permission):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if not current_user.can(permission):
				abort(403)
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def admin_required(f):
	return permission_required(Permission.ADMINISTER)(f)

@app.context_processor
def inject_permissions():
	return dict(Permission=Permission)

@app.route('/user/<username>', methods=['GET', 'POST'])
def user(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		abort(404)
	posts=Post.query.order_by(Post.timestamp.desc()).all()
	return render_template('user.html', user=user, posts=posts)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
	form = EditProfileForm()
	if form.validate_on_submit():
		current_user.name = form.name.data
		current_user.location = form.location.data
		current_user.about_me = form.about_me.data
		db.session.add(current_user)
		flash('Your profile has been updated.')
		return redirect(url_for('user', username=current.username))
	form.name.data = current_user.name
	form.location.data = current_user.location
	form.about_me.data = current_user.about_me
	return render_template('edit_profile.html', form=form)

@app.route('/edit-profile/<int:id>', methods=['GET','POST'])
@login_required
@admin_required
def edit_profile_admin(id):
	user = User.query.get_or_404(id)
	form = EditProfileAdminForm(user=user)
	if form.validate_on_submit():
		user.email = form.email.data
		user.username = form.username.data
		user.confirmed = form.confirmed.data
		user.role = Role.query.get(form.role.data)
		user.name = form.name.data
		user.location = form.location.data
		user.about_me = form.about_me.data
		db.session.add(user)
		flash('The profile has been updated.')
		return redirect(url_for('user', username=user.username))
	form.email.data = user.email
	form.username.data = user.username
	form.confirmed.data = user.confirmed
	form.role.data = user.role_id
	form.name.data = user.name
	form.location.data = user.location
	form.about_me.data = user.about_me
	return render_template('edit_profile.html', form=form, user=user)

@app.route('/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit(id):
	post = Post.query.get_or_404(id)
	if current_user != post.author and \
		not current_user.can(Permission.ADMINISTER):
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.body = form.body.data
		db.session.add(post)
		flash('The post has been updated.')
		return	redirect(url_for('post',id=post.id))
	form.body.data = post.body
	return render_template('edit_post.html', form=form)

@app.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('Invalid User')
		return redirect(url_for('index'))
	if current_user.is_following(user):
		flash('You are already following this user.')
		return redirect(url_for('user', username=username))
	current_user.follow(user)
	flash('You are now following %s.' % username)
	return redirect(url_for('user', username=username))

@app.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('Invalid user.')
		return redirect(url_for('index'))
	if not current_user.is_following(user):
		flash('You are not following this user') 
	current_user.unfollow(user)
	flash('You are not following %s anymore' % username)
	return redirect(url_for('user', username=username))

@app.route('/followers/<username>')
def followers(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('Invalid user.')
		return redirect(url_for('index'))
	page = request.args.get('page', 1, type=int)
	pagination = user.followers.paginate(
		page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
		error_out=False)
	follows = [{'user': item.follower, 'timestamp':item.timestamp}
				for item in pagination.items]
	return render_template('followers.html', user=user, title="Follows of",
							endpoint='followers', pagination=pagination,
							follows=follows)

@app.route('/followed-by/<username>')
def followed_by(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('Invalid user.')
		return redirect(url_for('index'))
	page = request.args.get('page', 1, type=int)
	pagination = user.followed.paginate(
		page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
		error_out=False)
	follows = [{'user': item.followed, 'timestamp': item.timestamp}
				for item in pagination.items]
	return render_template('followers.html', user=user, title="Follow of",
							 endpoint='followed_by', pagination=pagination,
							 follows=follows)

@app.route('/all')
@login_required
def show_all():
	resp = make_response(redirect(url_for('index')))
	resp.set_cookie('show_followed', '', max_age=30*24*60*60)
	return resp

@app.route('/followed')
@login_required
def show_followed():
	resp = make_response(redirect(url_for('index')))
	resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
	return resp

@app.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
	post = Post.query.get_or_404(id)
	form = CommentForm()
	if form.validate_on_submit():
		comment = Comment(body=form.body.data,
						author=current_user._get_current_object(),
						post = post)
		db.session.add(comment)
		flash('Your comment has been pulished.')
		return redirect(url_for('post', id=post.id, page= -1))
	page = request.args.get('page', 1, type=int)
	if page == -1:
		page = (post.comments.count() -1)/ \
				current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
	pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
		page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
		error_out=False)
	comments = pagination.items
	return render_template('post.html', posts=[post], form=form,
							comments=comments, pagination=pagination)

@app.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
	page = request.args.get('page', 1, type=int)
	pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(page,
		per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
		error_out=False)
	comments = pagination.items
	return render_template('moderate.html',comments=comments,
		pagination=pagination,page=page)

@app.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
	comment = Comment.query.get_or_404(id)
	comment.disabled = False
	db.session.add(comment)
	return redirect(url_for('moderate', page=request.args.get('page', 1, type=int)))

@app.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
	comment = Comment.query.get_or_404(id)
	comment.disabled = True
	db.session.add(comment)
	return redirect(url_for('moderate', page=request.args.get('page', 1,type=int)))



if __name__ =='__main__':
	manager.run()





