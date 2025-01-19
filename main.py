from sqlite3 import IntegrityError
import secrets
from forms import ContactForm, LoginForm, RegistrationForm, GenderForm, ProfileForm,EditUserForm,DeleteUserForm,ForgotPasswordForm,OTPForm,ResetPasswordForm,ProductEditForm,DeleteProductForm,AddProductForm,AddCategoryForm,CategoryForm
from flask import Flask, render_template, Response, request, redirect, flash, url_for, session, abort
import cv2
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, DateTime, Boolean, Float, ForeignKey,JSON
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import requests
import smtplib
from pip._vendor import cachecontrol
from functools import wraps
from datetime import datetime
from deepface import DeepFace
from pprint import pprint
from flask_socketio import SocketIO, emit
import google.auth.transport.requests



app = Flask(__name__)



load_dotenv()

# Google OAuth configuration
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP traffic for local dev
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://127.0.0.1:5001/callback")

# Initialize Google OAuth flow
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
    redirect_uri=REDIRECT_URI,
)


app.config['SECRET_KEY'] = os.getenv('API_KEY')
MAIL_ADDRESS = os.environ.get("EMAIL_KEY")
MAIL_APP_PW = os.environ.get("PASSWORD_KEY")
API_KEY = os.environ.get("API_KEY")
# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route("/test")
def test():
    form = GenderForm()
    return render_template('gender.html',form = form)

# Create a user_loader callback to reload the user from the user_id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If the current user's ID is not 1, render an access denied template and abort
        if current_user.id != 1:
            # Optionally log the unauthorized access attempt here
            return render_template('404.html'), 403  # Return 403 status code
        # Otherwise, continue with the route function
        return f(*args, **kwargs)

    return decorated_function

# Base class for models
class Base(db.Model):
    __abstract__ = True

class User(UserMixin, Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    gender: Mapped[str] = mapped_column(String(50), nullable=True)

    # Relationship with Report table
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="user", cascade="all, delete-orphan")

class Report(Base):
    __tablename__ = 'reports'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    smiles_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    access_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    streak_counter: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_access_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationship with User table
    user: Mapped["User"] = relationship("User", back_populates="reports")

# Create the database
with app.app_context():
    db.create_all()
@app.route('/')
def home():
    is_admin = current_user.is_authenticated and current_user.id == 1
    first_name = current_user.first_name if current_user.is_authenticated else 'N/A'
    last_name = current_user.last_name if current_user.is_authenticated else 'N/A'

    form = ContactForm()
    return render_template('home.html',is_admin=is_admin,
                           first_name=first_name,
                           last_name=last_name,
                           logged_in=current_user.is_authenticated,
                           form = form
                           )
@app.route('/submit', methods=['POST'])
def submit():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        subject = form.subject.data
        send_email(name, email, subject, message)
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('home') + "#contact")  # Redirect to home and scroll to contact section

    flash('There was an issue with your submission.', 'error')
    return redirect(url_for('home') + "#contact")


@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logs out the user from the Flask session
    session.clear()  # Clear the session
    return redirect(url_for('home'))

#send email
def send_email(name, email, subject, message):
    email_message = f"Subject: {subject}\n\nName: {name}\nEmail: {email}\nMessage: {message}"
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(MAIL_ADDRESS, MAIL_APP_PW)
        connection.sendmail(MAIL_ADDRESS, email, email_message)

@app.route('/google/login')
def google_login():
    authorization_url, state = flow.authorization_url(prompt='select_account')
    session["state"] = state  # Store state for verification
    return redirect(authorization_url)

@app.route('/callback')
def google_callback():
    try:
        flow.fetch_token(authorization_response=request.url)

        if session.get("state") != request.args.get("state"):
            abort(500)  # State does not match! Potential CSRF attack

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        # Verify the ID token
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        # Add a grace period
        issued_at = id_info.get("iat")
        expiration_time = id_info.get("exp")

        current_time = datetime.utcnow().timestamp()

        # If the token is not yet valid, allow a 1-minute grace period
        if issued_at > current_time + 60:  # Token used too early
            flash('Token is not yet valid. Please try again later.', 'danger')
            return redirect(url_for('login'))

        email = id_info.get("email")
        first_name = id_info.get("given_name") or "N/A"
        last_name = id_info.get("family_name") or "N/A"

        # Check if the user exists in the local database
        user = User.query.filter_by(email=email).first()

        hashed_password = generate_password_hash("it was googled", method='pbkdf2:sha256')
        if not user:
            # Create a new user without a password
            user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Account created successfully! Please provide your gender.', 'success')
            return redirect(url_for('gender', email=email))
        else:
            login_user(user)
            return redirect(url_for('home'))

    except Exception as e:
        flash(f'An error occurred during the login process: {str(e)}', 'danger')
        return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            # Update user profile logic here
            current_user.first_name = form.first_name.data
            current_user.last_name = form.last_name.data
            current_user.gender = form.gender.data

            # Save changes to the database
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('profile'))

    # Populate form fields with current user data for display
    if request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.gender.data = current_user.gender

    return render_template('profile.html', form=form, user=current_user)


def otp_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if OTP has been verified
        if 'otp_verified' not in session or not session['otp_verified']:
            flash('Please verify your OTP/email before resetting your password.', 'danger')
            return redirect(url_for('otp'))  # Redirect to OTP verification page
        return f(*args, **kwargs)
    return decorated_function


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        logout_user()
        session.clear()
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if check_password_hash(existing_user.password,'it was googled'):  # Assuming you have a field to check this
                flash(
                    'You cannot reset your password for this Google account. Try logging with Google.',
                    'warning')
                return redirect(url_for('login'))

            generated_OTP = rand_otp()
            session['OTP'] = generated_OTP
            message = (f"Dear {existing_user.first_name},\n"
                       f"Your one-time password (OTP) is: {generated_OTP}\n"
                       "Please use this code to complete your login or verification process. "
                       "This OTP is valid for 10 minutes and can only be used once.\n"
                       "If you did not request this code, please ignore this message.\n"
                       "Thank you,\nGizmo")
            subject = "Verification Code: Complete Your Login"
            send_email(existing_user.first_name, "anirudh050504@gmail.com", subject, message)  # Send to user's email
            flash('OTP sent successfully', 'success')
            session['user_email'] = email  # Store email in session for later use
            session['otp_timestamp'] = datetime.now().timestamp()
            return redirect(url_for('otp'))
        flash('Email not found in our system. Please register to create an account and log in.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'user_email' not in session:
        flash('Please enter your registered email first.', 'danger')
        return redirect(url_for('forgot_password'))
    form = OTPForm()
    if form.validate_on_submit():
        otp_value = int(form.otp.data)
        current_time = datetime.now().timestamp()
        otp_timestamp = session.get('otp_timestamp', 0)

        if otp_value == int(session.get('OTP')) and (current_time - otp_timestamp < 600):  # Check if OTP is valid for 10 minutes
            flash('OTP verified. You can now reset your password!', 'success')
            session['otp_verified'] = True
            return redirect(url_for('reset_password'))
        flash('OTP is incorrect or expired', 'danger')
        return redirect(url_for('otp'))
    return render_template('otp.html', form=form)


def rand_otp():
    otp = [secrets.randbelow(10) for _ in range(6)]
    return ''.join(map(str,otp))

@app.route('/resend_otp', methods=['GET','POST'])
def resend_otp():
    if 'user_email' not in session:
        flash('Please enter your registered email first.', 'danger')
        return redirect(url_for('forgot_password'))

    current_time = datetime.now().timestamp()
    otp_timestamp = session.get('otp_timestamp', 0)

    if current_time - otp_timestamp >= 120:  # Check if 2 minutes have passed since last OTP
        generated_OTP = rand_otp()
        session['OTP'] = generated_OTP  # Update OTP in session
        email = session['user_email']
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            message = (f"Dear {existing_user.first_name},\n"
                       f"Your new one-time password (OTP) is: {generated_OTP}\n"
                       "Please use this code to complete your login or verification process. "
                       "This OTP is valid for 10 minutes and can only be used once.\n"
                       "If you did not request this code, please ignore this message.\n"
                       "Thank you,\nGizmo")
            subject = "Verification Code: Complete Your Login"
            send_email(existing_user.first_name, "anirudh050504@gmail.com", subject, message)  # Send new OTP
            session['otp_timestamp'] = current_time  # Update the OTP timestamp
            flash('New OTP sent successfully', 'success')
        else:
            flash('Email not found in our system.', 'danger')
    else:
        remaining_time = 120 - (current_time - otp_timestamp)
        flash(f'Please wait {int(remaining_time)} seconds before requesting a new OTP.', 'warning')

    return redirect(url_for('otp'))



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        password = form.password.data
        repeated_password = form.repeat_password.data
        gender = form.gender.data


        # Uncomment to enable user registration logic
        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))

        try:
            # Check if the password and repeated password match
            if password != repeated_password:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            # Create a new user and add to the database
            new_user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password, gender=gender)
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            # Rollback in case of IntegrityError
            # db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return redirect(url_for('register'))

        except Exception as e:
            # Rollback in case of other errors
            # db.session.rollback()
            flash('Error occurred while creating account: {}'.format(str(e)), 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

























# Initialize the webcam
camera = cv2.VideoCapture(0)

# Load a pre-trained face detection model
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# Threshold for minimum face size to ensure the face is close enough
MIN_FACE_SIZE = 100


@app.route('/gender<email>', methods=["GET", "POST"])
@login_required
def gender(email):
    form = GenderForm()  # Assume you have a form defined to collect gender
    user = User.query.filter_by(email=email).first()  # Fetch user info based on email

    if form.validate_on_submit():
        gender = form.gender.data
        user.gender = gender  # Update the user's gender
        db.session.commit()  # Commit the changes to the database
        return redirect(url_for('home'))  # Redirect to home after updating

    return render_template('gender.html', form=form, user=user)



@app.route('/video_feed')
def video_feed():
    def generate_frames():
        while True:
            success, frame = camera.read()
            if not success:
                break
            else:
                # Resize the frame to make it smaller
                frame = cv2.resize(frame, (300, 300))

                # Convert to grayscale for face detection
                gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Detect faces
                faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(30,30))

                # Encode frame to JPEG format
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/shoot', methods=['GET','POST'])
def shoot():
    return render_template('index.html')

@app.route('/capture', methods=['POST'])
def capture():
    success, frame = camera.read()
    if not success:
        print("Error: Failed to capture image.")
        flash('Failed to capture image.', 'error')
        return redirect(url_for('shoot'))

    if success:
        # Convert to grayscale for face detection
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))

        if len(faces) == 0:
            flash('No face detected. Please move closer to the camera.', 'error')
            return redirect(url_for('shoot'))

        for (x, y, w, h) in faces:
            if w >= MIN_FACE_SIZE and h >= MIN_FACE_SIZE:
                # Crop the face region
                face_frame = frame[y:y + h, x:x + w]

                # Resize and save the face region
                face_frame = cv2.resize(face_frame, (400, 400))
                save_path = os.path.join('static', 'captured_image.jpg')
                cv2.imwrite(save_path, face_frame)

                # Analyze the captured image for emotions
                try:
                    analysis = DeepFace.analyze(save_path, actions=['emotion'])

                    # Extract the emotions and their confidence scores
                    emotion_scores = analysis[0]['emotion']

                    # Find the emotion with the highest score
                    dominant_emotion = max(emotion_scores, key=emotion_scores.get)
                    dem_em = "happy" if dominant_emotion == 'happy' else "not happy"

                    # Save the image and emotion in the session
                    session['captured_image'] = save_path
                    session['dominant_emotion'] = dem_em

                    flash('Image captured and analyzed successfully!', 'success')
                    return redirect(url_for('captured'))

                except Exception as e:
                    flash(f'Failed to analyze image: Reposition Yourself', 'error')
                    return redirect(url_for('shoot'))

        flash("Face detected but not close enough. Please move closer.", 'warning')
        return redirect(url_for('shoot'))

    flash('Failed to capture image.', 'error')
    return redirect(url_for('shoot'))

@app.route('/chatbot', methods=['GET','POST'])
def chatbot():
    return render_template('chatbot.html')

@app.route('/captured')
def captured():
    captured_image = session.get('captured_image', None)
    dominant_emotion = session.get('dominant_emotion', None)
    return render_template('captured.html', captured_image=captured_image, dominant_emotion=dominant_emotion)

@app.route('/retry')
def retry():
    # Remove the captured image and emotion from the session to allow retry
    session.pop('captured_image', None)
    session.pop('dominant_emotion', None)
    flash('You can now retake your image.', 'info')
    return redirect(url_for('shoot'))



if __name__ == '__main__':
    try:
        app.run(debug=True,port=5001)
    except Exception as e:
        print(f"Error occurred: {str(e)}")
