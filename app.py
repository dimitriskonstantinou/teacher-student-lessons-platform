from flask import Flask, render_template, request, redirect, session, make_response, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_migrate import Migrate

app = Flask(__name__)

# MySQL database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/signup_table'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db = SQLAlchemy(app)
migrate = Migrate(app, db)#to make every change in the data base in case

# User model
class User(db.Model):    
    __tablename__ = 'users'
     
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    
    student_courses = db.Table('student_courses',
        db.Column('student_id', db.Integer, db.ForeignKey('users.id')),
        db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
    )
    
    courses = db.relationship('Course', backref='teacher', lazy=True)
    registered_courses = db.relationship('Course', secondary=student_courses, backref='students', lazy='dynamic')
    
    

class Course(db.Model):
    __tablename__ = 'courses'
    
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return role_dashboard(user.role)
        session.clear()
        
    teachers = User.query.filter_by(role='teacher').all()
        
    response = make_response(render_template('home.html', teachers = teachers))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return role_dashboard()

    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']
        role = request.form['role']

        # Check for existing email or phone
        if User.query.filter_by(email=email).first():
            flash("Email is already registered.", "danger")
        elif User.query.filter_by(phone=phone).first():
            flash("Phone number is already registered.", "danger")
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(first_name=first_name, last_name=last_name, email=email,
                            phone=phone, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful!", "success")
            return redirect('/')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if 'user_id' in session and 'role' in session:
        return role_dashboard(session['role'])

    message = ""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['role'] = user.role
            return role_dashboard(user.role)
        else:
            message = "Invalid email or password"

    # Prevent caching the login page
    response = make_response(render_template('login.html', message=message))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

    
def role_dashboard(role):
    role= session.get('role')
    if role == 'admin':
        return redirect('/admin_dashboard')
    elif role == 'teacher':
        return redirect('/teacher_dashboard')
    elif role == 'student':
        return redirect('/student_dashboard')
    else:
        session.clear()
        return redirect('/login')
    
@app.route('/admin_dashboard', methods=['GET','POST'])
def admin_dashboard():
    if 'user_id' not in session: #check if the user is logged in
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    
    if not user or user.role != 'admin':
        return "Access denied", 403
    
    if request.method == 'POST':
        course_name = request.form.get('course_name', '').strip()
        description = request.form.get('description', '').strip()

        if course_name:  # Only add if course_name is provided
            new_course = Course(course_name=course_name, description=description)
            db.session.add(new_course)
            db.session.commit()
            flash("Course added successfully!")
        else:
            flash("Course name is required.")

        return redirect('/admin_dashboard')

    courses = Course.query.all()
    return render_template('admin_dashboard.html', user=user, courses=courses)

@app.route('/delete_course/<int:course_id>', methods=['POST'])
def delete_course(course_id):
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return "Access denied", 403

    course = Course.query.get_or_404(course_id)
    db.session.delete(course)
    db.session.commit()
    flash("Course deleted successfully!")
    return redirect('/admin_dashboard')


@app.route('/teacher_dashboard', methods=['GET', 'POST'])
def teacher_dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    if user.role != 'teacher':
        return "Access denied", 403

    if request.method == 'POST':
        selected_course_id = request.form.get('course_id')
        course = Course.query.get(selected_course_id)
        if course:
            course.teacher_id = user.id
            db.session.commit()
            flash("You have been assigned to the course.", "success")
        return redirect('/teacher_dashboard')

    # Get courses that are not assigned to anyone
    unassigned_courses = Course.query.filter_by(teacher_id=None).all()

    # Get courses already assigned to this teacher
    my_courses = Course.query.filter_by(teacher_id=user.id).all()

    return render_template('teacher_dashboard.html', user=user, unassigned_courses=unassigned_courses, my_courses=my_courses)



@app.route('/student_dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    if user.role != 'student':
        return "Access denied", 403

    if request.method == 'POST':
        course_id = request.form.get('course_id')
        course = Course.query.get(course_id)
        if course and course not in user.registered_courses:
            user.registered_courses.append(course)
            db.session.commit()
            flash("You have successfully registered for the course!", "success")
        return redirect('/student_dashboard')

    # Get all courses with teachers
    available_courses = Course.query.filter(Course.teacher_id.isnot(None)).all()
    my_courses = user.registered_courses.all()

    return render_template('student_dashboard.html', user=user, available_courses=available_courses, my_courses=my_courses)



#@app.route('/dashboard')
#def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    response = make_response(render_template('dashboard.html', user=user))
    response.headers['Cache-Control'] = 'no-store'
    return response



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/success')
def success():
    return '<h2>Registration successful!</h2><a href="/">Go Home</a>'

if __name__ == '__main__':
    app.run(debug=True)