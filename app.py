from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup
from PIL import Image

import os
import logging
import sys


if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
socketio = SocketIO(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'doc', 'docx', 'mp4', 'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename, filepath
    return None, None

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    created_problems = db.relationship('Problem', foreign_keys='Problem.user_id', backref='creator', lazy=True, cascade="all, delete-orphan")
    assigned_problems = db.relationship('Problem', foreign_keys='Problem.assigned_to', backref='assignee', lazy=True, overlaps='assignee')
    comments = db.relationship('Comment', back_populates='user', lazy=True)
    

class Problem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='New')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_assigned_to_user'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    priority = db.Column(db.String(50), default='Medium')
    category = db.Column(db.String(100), nullable=False)
    is_archived = db.Column(db.Boolean, default=False) 

    comments = db.relationship('Comment', back_populates='problem', cascade='all, delete-orphan', lazy=True)
    assigned_user = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_problems_user', lazy='joined', overlaps='assigned_problems')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey('problem.id'), nullable=False)
    files = db.relationship('CommentFile', back_populates='comment', cascade='all, delete-orphan')
   
    user = db.relationship('User', back_populates='comments')
    problem = db.relationship('Problem', back_populates='comments')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey('problem.id', ondelete='CASCADE'), nullable=False)

    problem = db.relationship('Problem', backref=db.backref('files', lazy=True, cascade='all, delete-orphan'))

class CommentFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id', ondelete='CASCADE'), nullable=False)

    comment = db.relationship('Comment', back_populates='files')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value

@app.route('/')
def home():
    return render_template('home.html')


logging.basicConfig(level=logging.DEBUG)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and/or password.', 'danger')
            logging.debug(f'Failed login attempt for username: {username}')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/submit_problem', methods=['GET', 'POST'])
@login_required
def submit_problem():
    file_errors = []
    file_success = []
    old_data = {}

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority')
        category = request.form.get('category')
        created_at_str = request.form.get('created_at')
        files = request.files.getlist('files')

        old_data = {
            'title': title,
            'description': description,
            'priority': priority,
            'category': category,
            'created_at': created_at_str,
        }

        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

        for file in files:
            if file and file.filename:
                fname = file.filename
                if not allowed_file(fname):
                    file_errors.append(f"Nie dostępny typ pliku: <code>{fname}</code>")
                    continue
                file.seek(0, 2)
                filesize = file.tell()
                file.seek(0)
                if filesize > MAX_FILE_SIZE:
                    file_errors.append(f"Za duży plik: <code>{fname}</code>")
                    continue
                ext = fname.rsplit('.', 1)[1].lower()
                if ext in {'png', 'jpg', 'jpeg', 'gif'}:
                    try:
                        img = Image.open(file)
                        img.verify()
                        file.seek(0)
                    except Exception:
                        file_errors.append(f"Uszkodzony plik: <code>{fname}</code>")
                        continue
                file_success.append(fname)

        if file_errors:
            from markupsafe import Markup
            for err in file_errors:
                flash(Markup(f"<strong>Błąd:</strong> {err}"), 'danger')
            if file_success:
                for ok in file_success:
                    flash(Markup(f"Plik <code>{ok}</code> została zweryfikowana, ale aplikacja nie została utworzona."), 'info')
            max_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M')
            return render_template('submit_problem.html', max_date=max_date, **old_data)

        if not title or not description or not priority or not category:
            flash("Wszystkie pola są wymagane!", 'danger')
            max_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M')
            return render_template('submit_problem.html', max_date=max_date, **old_data)

        created_at = datetime.utcnow() if not created_at_str else datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M')
        new_problem = Problem(
            title=title,
            description=description,
            priority=priority,
            category=category,
            created_at=created_at,
            user_id=current_user.id
        )
        db.session.add(new_problem)
        db.session.commit()

        # Save files
        for file in files:
            fname = file.filename
            if fname and allowed_file(fname):
                filename, filepath = save_file(file)
                if filename:
                    new_file = File(filename=filename, filepath=filepath, problem_id=new_problem.id)
                    db.session.add(new_file)
        db.session.commit()

        flash("Aplikacja została pomyślnie utworzona. Wszystkie pliki zostały przesłane.", "success")
        return redirect(url_for('problems'))

    max_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M')
    return render_template('submit_problem.html', max_date=max_date)




@app.route('/problems')
@login_required
def problems():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')
    category = request.args.get('category', 'all')
    priority = request.args.get('priority', 'all') 

    query = Problem.query.filter(Problem.is_archived == False)  

    if not current_user.is_admin:
        query = query.filter(Problem.user_id == current_user.id)
    if status != 'all':
        query = query.filter(Problem.status == status)
    if category != 'all':
        query = query.filter(Problem.category == category)
    if priority != 'all':
        query = query.filter(Problem.priority == priority)

    problems = query.order_by(Problem.created_at.desc()).paginate(page=page, per_page=51)
    if page > problems.pages and problems.pages > 0:
        return redirect(url_for('problems', page=problems.pages))
    return render_template('problems.html', problems=problems, filter_status=status, filter_category=category, filter_priority=priority)


@app.route('/problem/<int:problem_id>/delete', methods=['POST'])
@login_required
def delete_problem(problem_id):
    if not current_user.is_admin:
        abort(403)
    problem = Problem.query.get_or_404(problem_id)
    
    Comment.query.filter_by(problem_id=problem_id).delete()
    
    for file in problem.files:
        db.session.delete(file)
    
    db.session.delete(problem)
    db.session.commit()
    
    flash('Problem deleted', 'success')
    return redirect(url_for('problems'))



@app.route('/problem/<int:problem_id>/resolve', methods=['POST'])
@login_required
def resolve_problem(problem_id):
    if not current_user.is_admin:
        abort(403)
    problem = Problem.query.get_or_404(problem_id)
    if problem.assigned_user and problem.assigned_user.id != current_user.id:
        flash('You cannot resolve this problem because it is not assigned to you.', 'danger')
    else:
        problem.status = 'Resolved'
        db.session.commit()
        flash('Problem marked as resolved', 'success')
    return redirect(url_for('problem_details', problem_id=problem.id))

@app.route('/problem/<int:problem_id>/undo_resolution', methods=['POST'])
@login_required
def undo_resolution(problem_id):
    if not current_user.is_admin:
        abort(403)
    problem = Problem.query.get_or_404(problem_id)
    if problem.status != 'Resolved':
        flash('Problem is not resolved yet.', 'danger')
    else:
        problem.status = 'In Progress'
        db.session.commit()
        flash('Status reverted to In Progress', 'success')
    return redirect(url_for('problem_details', problem_id=problem.id))

@app.route('/problem/<int:problem_id>/comment', methods=['POST'])
@login_required
def comment_problem(problem_id):
    problem = Problem.query.get_or_404(problem_id)
    if problem.is_archived:
        flash('Zarchiwizowanych zgłoszeń nie można komentować.', 'danger')
        return redirect(url_for('problem_details', problem_id=problem.id))
 
    content = request.form.get('content')
    files = request.files.getlist('files')

    if content:
        new_comment = Comment(content=content, user_id=current_user.id, problem_id=problem_id)
        db.session.add(new_comment)
        db.session.commit()
        socketio.emit('new_comment', {
            'problem_id': problem_id,
            'content': content,
            'author': current_user.username,
            'is_admin': current_user.is_admin
        })

        for file in files:
            if file and allowed_file(file.filename):
                filename, filepath = save_file(file)
                if filename:
                    new_file = CommentFile(
                        filename=filename, filepath=filepath, comment_id=new_comment.id
                    )
                    db.session.add(new_file)
        db.session.commit()

    return redirect(url_for('problem_details', problem_id=problem_id))



@app.route('/download/comment_file/<filename>')
@login_required
def download_comment_file(filename):
    file = CommentFile.query.filter_by(filename=filename).first_or_404()
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/problem/<int:problem_id>')
@login_required
def problem_details(problem_id):
    problem = Problem.query.get_or_404(problem_id)
    if not current_user.is_admin and problem.user_id != current_user.id:
        abort(403)
    comments = Comment.query.filter_by(problem_id=problem_id).all()
    return render_template('problem_details.html', problem=problem, comments=comments)


@app.route('/problem/<int:problem_id>/assign', methods=['POST'])
@login_required
def assign_problem(problem_id):
    if not current_user.is_admin:
        abort(403)
    problem = Problem.query.get_or_404(problem_id)
    if problem.assigned_user and problem.assigned_user.id != current_user.id:
        flash('Problem is already assigned to another user.', 'danger')
    else:
        problem.assigned_user = current_user
        db.session.commit()
        flash('Problem assigned to you.', 'success')
    return redirect(url_for('problem_details', problem_id=problem.id))

@app.route('/problem/<int:problem_id>/set_in_progress', methods=['POST'])
@login_required
def set_in_progress(problem_id):
    if not current_user.is_admin:
        abort(403)
    try:
        problem = Problem.query.get_or_404(problem_id)
        if problem.status != 'New':
            flash('You can only set a problem to In Progress if it is in New status.', 'danger')
        else:
            problem.status = 'In Progress'
            db.session.commit()
            flash('Problem status set to In Progress.', 'success')
    except Exception as e:
        logger.error(f"Error setting problem status to In Progress: {e}")
        flash('An error occurred while setting the problem status.', 'danger')
    return redirect(url_for('problem_details', problem_id=problem.id))



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    files = request.files.getlist('file')
    if len(files) > 5:
        return "Można przesłać maksymalnie 5 plików", 400
    
    for file in files:
        if file.filename == '':
            continue
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    if allowed_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        abort(404)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        abort(403) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        if username and password:
            hashed_password = generate_password_hash(password) 
            new_user = User(username=username, password=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_users'))
        else:
            flash('Username and password are required!', 'danger')

    return render_template('create_user.html')


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.')
    else:
        flash('User not found.')
    return redirect(url_for('admin_users'))

@app.route('/archive')
@login_required
def archive():
    if not current_user.is_admin:
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    archived_problems = Problem.query.filter(Problem.is_archived == True).order_by(Problem.created_at.desc()).paginate(page=page, per_page=5)

    return render_template('archive.html', problems=archived_problems)

@app.route('/problem/<int:problem_id>/archive', methods=['POST'])
@login_required
def archive_problem(problem_id):
    if not current_user.is_admin:
        abort(403)
    problem = Problem.query.get_or_404(problem_id)
    if problem.status != 'Archived':
        problem.is_archived = True
        problem.status = 'Archived'
        db.session.commit()
        flash('Problem has been archived.', 'success')
    else:
        flash('Problem is already archived.', 'warning')
    return redirect(url_for('problems'))

if __name__ == '__main__':
    socketio.run(app, debug=True)
