from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Trainer, Admin, Notification, Certification, Service, TrainerService, VerificationStatus
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from random import randint
from datetime import datetime, timedelta
from flask_migrate import Migrate
import os
from PIL import Image
import json



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pet_heaven.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'alpha'

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'companypethaven@gmail.com'
app.config['MAIL_PASSWORD'] = 'adgz kwhe mchu mrnj'


# Initialize extensions
db.init_app(app)
mail = Mail(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)


# Initialize Flask-Login's LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Create the database
with app.app_context():
    db.create_all()


# Configure upload settings
BASE_UPLOAD_FOLDER = os.path.join('static', 'images', 'UserData')  # Root folder for all user-specific images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Create root folder if it doesn't exist
os.makedirs(BASE_UPLOAD_FOLDER, exist_ok=True)

# Helper functions
def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compress_image(image_path):
    """Compress image to save storage space."""
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        img.save(image_path, optimize=True, quality=85)
    except Exception as e:
        print(f"Error compressing image: {e}")

def delete_old_profile_picture(file_path):
    """Delete old profile picture if it exists."""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        print(f"Error deleting old profile picture: {e}")
        return False

def get_user_folder(user_id):
    """Get the folder specific to the user (by user ID)."""
    # Create a folder for the user inside static/images/UserData/{user_id}/
    user_folder = os.path.join(BASE_UPLOAD_FOLDER, str(user_id))
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)  # Create folder if it doesn't exist
    return user_folder

def handle_profile_picture_upload(user_id, profile_picture):
    """Handle the upload of the profile picture."""
    user_folder = get_user_folder(user_id)  # Get or create the user's folder
    if profile_picture and profile_picture.filename != '':
        # Validate file type and size
        if allowed_file(profile_picture.filename):
            if profile_picture.content_length > MAX_FILE_SIZE:
                print('File size too large. Maximum size is 5MB.')
                return None  # Or you can use flash messages for error handling

            # Generate a unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(f"user_{user_id}_{timestamp}_{profile_picture.filename}")
            
            # Save the profile picture in the user's folder
            file_path = os.path.join(user_folder, filename)
            profile_picture.save(file_path)
            
            # Compress the image to optimize space
            compress_image(file_path)
            
            # Return the relative path to store in the database
            return f'images/UserData/{user_id}/{filename}'
    return None

def handle_certification_image_upload(user_id, cert_image):
    """Handle the upload of certification images."""
    user_folder = get_user_folder(user_id)  # Get or create the user's folder
    if cert_image and cert_image.filename != '':
        # Validate file type and size
        if allowed_file(cert_image.filename):
            if cert_image.content_length > MAX_FILE_SIZE:
                print('Certification image size too large. Maximum size is 5MB.')
                return None  # Or you can use flash messages for error handling

            # Generate a unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            cert_filename = secure_filename(f"cert_{user_id}_{timestamp}_{cert_image.filename}")
            
            # Save the certification image in the user's folder
            cert_file_path = os.path.join(user_folder, cert_filename)
            cert_image.save(cert_file_path)
            
            # Compress the image to optimize space
            compress_image(cert_file_path)
            
            # Return the relative path to store in the database
            return f'images/UserData/{user_id}/{cert_filename}'
    return None

def validate_certification_data(cert_name, cert_image):
    if not cert_name:
        return False
    if cert_image and cert_image.filename:
        if not allowed_file(cert_image.filename):
            return False
    return True

def handle_government_id_upload(user_id, file, id_type):
    """Handles the upload of government ID images."""
    if file and allowed_file(file.filename):
        print(f"Received file for {id_type}: {file.filename}")  # Debugging line
        filename = secure_filename(file.filename)
        
        # Define the base upload folder
        user_folder = get_user_folder(user_id)  # This will point to 'static/images/UserData/{user_id}'
        
        # Create a 'government' subfolder within the user's folder
        government_folder = os.path.join(user_folder, 'government')
        os.makedirs(government_folder, exist_ok=True)  # Create directory if it doesn't exist
        
        # Set the path based on the ID type
        if id_type == 'aadhaar':
            file_path = os.path.join(government_folder, f"aadhaar_{filename}")
        elif id_type == 'pan':
            file_path = os.path.join(government_folder, f"pan_{filename}")
        else:
            print("Invalid ID type provided.")  # Debugging line
            return None
        
        # Save the file
        file.save(file_path)
        print(f"File saved at: {file_path}")  # Debugging line
        
        # Return the relative path to store in the database
        return f'images/UserData/{user_id}/government/{os.path.basename(file_path)}'
    print("File upload failed: No file or invalid file type.")  # Debugging line
    return None
    

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to send OTP
def send_otp(email):
    try:
        # Generate OTP
        import random
        otp = str(random.randint(100000, 999999))
        
        # Send email
        msg = Message(
            "Your Login OTP", 
            sender=app.config['MAIL_USERNAME'], 
            recipients=[email]
        )
        msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
        mail.send(msg)
        
        # Optional: Log the OTP (remove in production)
        app.logger.info(f"OTP generated for {email}: {otp}")
        # Store the OTP generation time  
        otp_generation_time = datetime.utcnow().isoformat() 
       
        return otp, otp_generation_time
    
    except Exception as e:
        app.logger.error(f"OTP sending failed: {str(e)}")
        flash('Error sending OTP. Please try again.', 'danger')
        return None


@app.route('/')
def home():
    trainers = Trainer.query.filter_by(verified=VerificationStatus.PENDING).all()
    pending = Trainer.query.filter_by(verified=VerificationStatus.PENDING).count()
    active_users = User.query.count()  # Count active users
    service_providers = User.query.filter(User.role=='trainer').count()  # Count service providers
    return render_template('main_dashboard.html', user=current_user, active_users=active_users, service_providers=service_providers, trainers=trainers, pending=pending)


@app.route('/edit_profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    user = User.query.get_or_404(user_id)
    
    # Fetch all available services to pass to the template
    services = Service.query.all()
    
    # Fetch existing certifications for the user
    trainer = Trainer.query.filter_by(user_id=user.id).first()
    existing_certifications = Certification.query.filter_by(trainer_id=trainer.id).all() if trainer else []

    if request.method == 'POST':
        try:
            # Handle profile picture upload
            if 'profile_picture' in request.files and request.files['profile_picture'].filename != '':
                # Delete old profile picture only if a new one is uploaded
                old_profile_picture_path = os.path.join('static', user.profile_picture) if user.profile_picture else None
                if old_profile_picture_path and os.path.exists(old_profile_picture_path):
                    os.remove(old_profile_picture_path)

                # Upload the new profile picture
                profile_picture_path = handle_profile_picture_upload(user_id, request.files['profile_picture'])
                if profile_picture_path:
                    user.profile_picture = profile_picture_path

            if not trainer:
                trainer = Trainer(user_id=user.id)
                db.session.add(trainer)  # Add trainer to the session
                db.session.flush()  # Ensure trainer.id is available
                
            # Handle certifications
            certifications = request.form.getlist('certifications[]')
            certification_images = request.files.getlist('certification_images[]')

            # Convert existing certifications to a dictionary for easy lookup
            existing_cert_dict = {cert.name: cert for cert in existing_certifications}

            # Process certifications in the form
            for cert_name, cert_image in zip(certifications, certification_images):
                if cert_name:  # Only process if there's a name
                    if cert_name in existing_cert_dict:
                        # If the certification already exists, update it if an image is provided
                        if cert_image and cert_image.filename:
                            cert_image_path = handle_certification_image_upload(user_id, cert_image)
                            existing_cert_dict[cert_name].image_path = cert_image_path
                    else:
                        # Add new certification
                        cert_image_path = None
                        if cert_image and cert_image.filename:
                            cert_image_path = handle_certification_image_upload(user_id, cert_image)
                        new_certification = Certification(
                            name=cert_name,
                            trainer_id=trainer.id,
                            image_path=cert_image_path
                        )
                        db.session.add(new_certification)

            # Remove certifications not included in the form (deleted by the user)
            submitted_cert_names = set(certifications)
            for cert in existing_cert_dict.values():
                if cert.name not in submitted_cert_names:
                    # Check if there is a checkbox for this certification's removal
                    remove_cert = request.form.get(f'remove_certification_{cert.id}')
                    if remove_cert:
                        # Delete image from filesystem
                        if cert.image_path and os.path.exists(os.path.join('static', cert.image_path)):
                            os.remove(os.path.join('static', cert.image_path))
                        db.session.delete(cert)

            # Update user details
            if request.form.get('name'):
                user.name = request.form.get('name')

            if request.form.get('mobile_number'):
                mobile_number = request.form.get('mobile_number')
                # Basic mobile number validation
                if not mobile_number.isdigit() or len(mobile_number) != 10:
                    flash('Invalid mobile number format.', 'danger')
                    return redirect(request.url)
                user.mobile_number = mobile_number
            
            # Update trainer details
            if trainer:  # Ensure trainer exists
                if request.form.get('experience'):
                    trainer.experience = int(request.form.get('experience'))

                if request.form.get('specialization'):
                    trainer.specialization = request.form.get('specialization')

                # Handle availability schedule with validation
                availability_schedule = request.form.get('availability_schedule')
                if availability_schedule:
                    try:
                        # Attempt to decode the JSON
                        trainer.availability_schedule = json.loads(availability_schedule)
                    except json.JSONDecodeError:
                        flash('Invalid JSON format for availability schedule.', 'danger')
                        return redirect(request.url)
                else:
                    trainer.availability_schedule = None  # Or set a default value

                if request.form.get('location'):
                    trainer.location = request.form.get('location')

                if request.form.get('bio'):
                    trainer.bio = request.form.get('bio')
            
            # Handle government ID uploads
            if 'aadhaar_image' in request.files and request.files['aadhaar_image'].filename != '':
                aadhaar_image_path = handle_government_id_upload(user_id, request.files['aadhaar_image'], 'aadhaar')
                if aadhaar_image_path:
                    trainer.aadhaar_image_path = aadhaar_image_path  # Update the trainer's Aadhaar path
                    print(f"Aadhaar image path updated: {aadhaar_image_path}")  # Debugging line
                else:
                    print("Failed to upload Aadhaar image.")  # Debugging line

            if 'pan_card_image' in request.files and request.files['pan_card_image'].filename != '':
                pan_image_path = handle_government_id_upload(user_id, request.files['pan_card_image'], 'pan')
                if pan_image_path:
                    trainer.pan_card_image_path = pan_image_path  # Update the trainer's PAN path
                    print(f"PAN image path updated: {pan_image_path}")  # Debugging line
                else:
                    print("Failed to upload PAN image.")  # Debugging line

            # Update services offered by the trainer
            services_selected = request.form.getlist('services[]')
            prices = request.form.getlist('prices[]')

            # Delete existing trainer services
            TrainerService.query.filter_by(trainer_id=trainer.id).delete()

            # Add new trainer services
            for service_id, price in zip(services_selected, prices):
                if service_id and price:
                    trainer_service = TrainerService(
                        trainer_id=trainer.id,
                        service_id=int(service_id),
                        price=float(price)
                    )
                    db.session.add(trainer_service)

            # Commit all changes
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile: {e}")
            flash('An error occurred while updating the profile.', 'danger')
            return redirect(request.url)

    return render_template('edit_profile.html', trainer=trainer, user=user, services=services, certifications=existing_certifications)

@app.route('/get_verified', methods=['POST'])
@login_required
def get_verified():
    # Fetch the trainer associated with the current user
    trainer = Trainer.query.filter_by(user_id=current_user.id).first()
    
    if trainer:
        # Update the verified status to 'pending'
        trainer.verified = VerificationStatus.PENDING
        db.session.commit()  # Save changes to the database
        flash('Your verification request has been submitted!', 'success')
    else:
        flash('Trainer not found!', 'danger')
    
    return redirect(url_for('profile'))  # Redirect back to the profile page


@app.route('/view_profile/<int:trainer_id>')
@login_required
def view_profile(trainer_id):
    # Fetch the trainer using the trainer_id
    trainer = Trainer.query.get_or_404(trainer_id)  # This will raise a 404 if the trainer is not found
    user = trainer.user  # Get the associated user for the trainer
    return render_template('profile_view_details.html', trainer=trainer, user=user)

@app.route('/update_trainer_status', methods=['POST'])
def update_trainer_status():
    trainer_id = request.form.get('trainer_id')
    action = request.form.get('action')

    # Find the trainer in the database
    trainer = Trainer.query.get(trainer_id)
    if not trainer:
        flash('Trainer not found', 'error')
        return redirect(url_for('home'))  # Redirect to an appropriate view

    # Update the trainer's status based on the action
    if action == 'accept':
        trainer.verified = 'approved'  # Update to approved
        message_body = f"Dear {trainer.user.name}, your application has been accepted."
    elif action == 'reject':
        trainer.verified = 'rejected'  # Update to rejected
        message_body = f"Dear {trainer.user.name}, your application has been rejected."
    else:
        flash('Invalid action', 'error')
        return redirect(url_for('home'))  # Redirect to an appropriate view

    # Commit the changes to the database
    db.session.commit()

    # Send email notification (optional)
    msg = Message('Trainer Application Status Update',
                  sender=app.config['MAIL_USERNAME'],  # Replace with your sender email
                  recipients=[trainer.user.email])
    msg.body = message_body
    mail.send(msg)

    flash(f'Trainer {action} successfully!', 'success')
    return redirect(url_for('home'))  # Redirect to an appropriate view after processing


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/services')
@login_required
def services():
    services = Service.query.all()
    return render_template('trainer_services.html', services=services)

@app.route('/add_service', methods=['POST'])
@login_required
def add_service():
    if current_user.role != 'admin':
        flash('You do not have permission to add services.', 'danger')
        return redirect(url_for('services'))

    name = request.form['name']
    description = request.form['description']
    
    # Check if the post request has the file part
    if 'image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('services'))
    
    file = request.files['image']
    
    # If the user does not select a file, the browser submits an empty file without a filename
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('services'))
    
    # Check if the file is allowed
    if file and allowed_file(file.filename):
        # Define the services_image folder directly in the route
        services_image_folder = os.path.join(BASE_UPLOAD_FOLDER, 'services_image')

        # Ensure the services_image directory exists
        if not os.path.exists(services_image_folder):
            os.makedirs(services_image_folder)

        filename = secure_filename(file.filename)
        file.save(os.path.join(services_image_folder, filename))
        image_path = os.path.join('static', 'images', 'UserData', 'services_image', filename).replace('\\', '/')  # Save the path to the database

        new_service = Service(name=name, description=description, image=image_path)
        db.session.add(new_service)
        db.session.commit()

        flash('Service added successfully!', 'success')
        return redirect(url_for('services'))
    else:
        flash('Invalid file type. Only PNG, JPG, and JPEG are allowed.', 'danger')
        return redirect(url_for('services'))

@app.route('/edit_service', methods=['POST'])
@login_required
def edit_service():
    if current_user.role != 'admin':
        flash('You do not have permission to edit services.', 'danger')
        return redirect(url_for('services'))

    service_id = request.form['service_id']
    service = Service.query.get(service_id)

    if service:
        service.name = request.form['name']
        service.description = request.form['description']
        
        # Check if a new file is being uploaded
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                # Define the services_image folder directly in the route
                services_image_folder = os.path.join(BASE_UPLOAD_FOLDER, 'services_image')

                # Ensure the services_image directory exists
                if not os.path.exists(services_image_folder):
                    os.makedirs(services_image_folder)

                filename = secure_filename(file.filename)
                file.save(os.path.join(services_image_folder, filename))
                service.image = os.path.join('static', 'images', 'UserData', 'services_image', filename).replace('\\', '/')  # Update the image path

        db.session.commit()
        flash('Service updated successfully!', 'success')
    else:
        flash('Service not found.', 'danger')

    return redirect(url_for('services'))

@app.route('/delete_service/<int:service_id>', methods=['GET'])
@login_required
def delete_service(service_id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete services.', 'danger')
        return redirect(url_for('services'))

    service = Service.query.get(service_id)
    if service:
        db.session.delete(service)
        db.session.commit()
        flash('Service deleted successfully!', 'success')
    else:
        flash('Service not found.', 'danger')

    return redirect(url_for('services'))

@app.route('/service/<int:service_id>/trainers')
def list_trainers(service_id):
    # Get the service by ID
    service = Service.query.get_or_404(service_id)
    
    # Query for trainers associated with the service and verified
    approved_trainers = (
        db.session.query(Trainer, TrainerService.price)
        .join(TrainerService)
        .filter(
            TrainerService.service_id == service.id,
            Trainer.verified == VerificationStatus.APPROVED
        )
        .all()
    )
    
    return render_template('trainers_list.html', trainers=approved_trainers, service=service)


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     # Check the role of the current user
#     # if current_user.role == 'admin':
#     #     return render_template('main_dashboard.html', user=current_user)
#     # else:
#         # return render_template('dashboard.html', user=current_user)
#     notifications = Notification.query.order_by(Notification.created_at.desc()).all()
#     unread_count = Notification.query.filter_by(read=False).count()  # Count unread notifications
#     return render_template('main_dashboard1.html', user=current_user, notifications=notifications, unread_count=unread_count)
    
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if the user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Check if all required fields are filled
        if not name or not email or not password or not confirm_password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        # Check if mobile number already exists (optional but recommended)
        if mobile:
            existing_mobile = User.query.filter_by(mobile_number=mobile).first()
            if existing_mobile:
                flash('Mobile number already exists. Please use a different number.', 'danger')
                return redirect(url_for('register'))
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Generate and send OTP
        otp,otp_generation_time = send_otp(email)
        
        if otp:
            # Store registration details in session
            session['registration_details'] = {
                'name': name,
                'mobile': mobile,
                'email': email,
                'password': hashed_password,
                'role': role
            }
            session['verification_type'] = 'registration'
            session['verification_otp'] = otp
            session['otp_generation_time'] = otp_generation_time
            
            flash('OTP sent to your email for registration verification', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Collect login data
        role = request.form.get('role', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = 'remember' in request.form  # Check if remember me is checked

        # Validation
        if not email or not password or not role:
            flash('Role, email, and password are required', 'danger')
            return render_template('login.html')
        
        # Find user
        # user_role = User.query.filter_by(role=role).first()
        # print(user_role)
        user = User.query.filter_by(email=email, role=role).first()
        
        # Authenticate
        if user and check_password_hash(user.password, password):
            if user.role != role:  
                flash(f'Incorrect role selected. Your role is {user.role}.', 'danger')
                return render_template('login.html')
            # Generate OTP
            otp,otp_generation_time  = send_otp(email)
            
            # Store session data for OTP verification
            session['login_email'] = email
            session['remember_me'] = remember  # Store remember me preference
            session['verification_type'] = 'login'
            session['verification_otp'] = otp
            session['otp_generation_time'] = otp_generation_time
            
            flash('OTP sent to your email', 'info')
            return redirect(url_for('verify_otp'))
        
        # Invalid credentials or role mismatch
        # if not user:
        #     flash('Invalid email, password, or role. Please try again.', 'danger')
        # else:
        flash('Invalid email or password', 'danger')
    
    return render_template('login.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Determine verification type
    verification_type = session.get('verification_type')
    
    # Check if necessary session data exists
    if verification_type == 'login':
        if 'login_email' not in session:
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
    elif verification_type == 'registration':
        if 'registration_details' not in session:
            flash('Session expired. Please start registration again.', 'warning')
            return redirect(url_for('register'))
    else:
        flash('Invalid verification attempt.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get user input
        entered_otp = request.form.get('otp', '')
        
        # Get the stored OTP and its generation time  
        stored_otp, otp_generation_time = session.get('verification_otp'), session.get('otp_generation_time')  
       
        # Check if the OTP has expired (10 minutes)  
        otp_generation_time = datetime.fromisoformat(session.get('otp_generation_time'))
        otp_expiration_time = otp_generation_time + timedelta(minutes=10)
        if datetime.utcnow() > otp_expiration_time:
            flash('OTP has expired.', 'danger')
            return redirect(url_for('resend_otp'))


        # Verify OTP
        if entered_otp == stored_otp:
            if verification_type == 'login':
                # Find user and log in
                user = User.query.filter_by(email=session['login_email']).first()
                
                if user:
                    # Use the remembered preference from session
                    remember_me = session.get('remember_me', False)
                    
                    # Update last login time
                    user.last_login = datetime.utcnow()
                    
                    # Log in the user
                    login_user(user, remember=remember_me)
                    
                    db.session.commit()
                    
                    # Clear session data
                    session.pop('login_email', None)
                    session.pop('remember_me', None)
                    session.pop('verification_type', None)
                    session.pop('verification_otp', None)
                    
                    try:
                        msg = Message(
                            "Login Successful!",
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[user.email]
                        )
                        msg.body = f"Dear {user.name},\n\nYou have successfully logged into your account on Pet Heaven.\n\nBest Regards,\nPet Heaven Team"
                        mail.send(msg)
                    except Exception as e:
                        app.logger.error(f"Failed to send login email: {str(e)}")
                        flash('Login email could not be sent. Please check your inbox later.', 'warning')
                    
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
            
            elif verification_type == 'registration':
                # Retrieve registration details from session
                reg_details = session['registration_details']
                
                # Create new user
                new_user = User(
                    name=reg_details['name'],
                    mobile_number=reg_details['mobile'],
                    email=reg_details['email'],
                    password=reg_details['password'],
                    role=reg_details['role']
                )
                
                # Add and commit to database
                db.session.add(new_user)
                db.session.commit()
                
                # Create a notification for the admin
                notification_message = f"New {new_user.role} registered: {new_user.name} ({new_user.email})"
                new_notification = Notification(
                                message=notification_message,
                                user_id=new_user.id  # Link the notification to the user
                            )
                db.session.add(new_notification)
                db.session.commit()
                
                # Emit the notification to all connected clients
                socketio.emit('new_notification', {'message': notification_message, 'created_at': datetime.utcnow().isoformat()})
                
                # **Send Registration Confirmation Email**
                try:
                    msg = Message(
                        "Registration Successful!",
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[reg_details['email']]
                    )
                    msg.body = f"Dear {reg_details['name']},\n\nThank you for registering on Pet Heaven. Your account has been created successfully.\n\nBest Regards,\nPet Heaven Team"
                    mail.send(msg)
                except Exception as e:
                    app.logger.error(f"Failed to send registration email: {str(e)}")
                    flash('Registration email could not be sent. Please check your inbox later.', 'warning')
                
                # Clear session data
                session.pop('registration_details', None)
                session.pop('verification_type', None)
                session.pop('verification_otp', None)
                
                flash('Registration Successful! You can now log in.', 'success')
                return redirect(url_for('login'))
        
        # Invalid OTP
        flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html')



@app.route('/resend_otp')
def resend_otp():
    # Determine verification type
    verification_type = session.get('verification_type')
    
    if verification_type == 'login':
        if 'login_email' in session:
            email = session['login_email']
    elif verification_type == 'registration':
        if 'registration_details' in session:
            email = session['registration_details']['email']
    else:
        flash('Invalid verification attempt.', 'warning')
        return redirect(url_for('login'))
    
    # Resend OTP
    new_otp,new_otp_generation_time  = send_otp(email)
    
    if new_otp:
        # Update the OTP in the session
        session['verification_otp'] = new_otp
        session['otp_generation_time'] = new_otp_generation_time
        flash('A new OTP has been sent to your email.', 'info')
    else:
        flash('Failed to send OTP. Please try again.', 'danger')
    
    return redirect(url_for('verify_otp'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        user = User.query.filter_by(email=email).first()
        if user:
            otp, otp_generation_time = send_otp(email)
            if otp:
                # Store reset data in session
                session['password_reset_email'] = email
                session['verification_otp'] = otp
                session['otp_generation_time'] = otp_generation_time
                
                flash('OTP sent to your email for password reset', 'info')
                return redirect(url_for('reset_password'))
            else:
                flash('Failed to send OTP. Please try again.', 'danger')
        else:
            # Use same message to prevent email enumeration
            flash('If the email exists in our system, you will receive a reset link.', 'info')
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Check if reset session exists
    if 'password_reset_email' not in session:
        flash('Password reset session expired. Please start over.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate OTP expiration
        otp_generation_time = datetime.fromisoformat(session.get('otp_generation_time'))
        if datetime.utcnow() - otp_generation_time > timedelta(minutes=10):
            # Clear expired session data
            email = session.pop('password_reset_email', None)
            session.pop('verification_otp', None)
            session.pop('otp_generation_time', None)
            flash('OTP has expired. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Verify OTP
        if otp != session.get('verification_otp'):
            flash('Invalid OTP. Please try again.', 'danger')
            return render_template('reset_password.html')
        
        # Validate password
        # if not validate_password(password):
        #     flash('Password must be at least 8 characters long and contain numbers, letters, and special characters.', 'danger')
        #     return render_template('reset_password.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password.html')
        
        try:
            # Update password
            email = session.get('password_reset_email')
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = generate_password_hash(password, method='pbkdf2:sha256')
                db.session.commit()
                
                # Clear all reset-related session data
                session.pop('password_reset_email', None)
                session.pop('verification_otp', None)
                session.pop('otp_generation_time', None)
                
                flash('Password updated successfully. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found. Please try again.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Password reset failed: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('reset_password.html')


@app.route('/dashboard/user_search', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in users can access this route
def user_search():
    users = []
    error_message = None

    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            # Try to find users with the given email
            users = User.query.filter_by(email=email).all()
            if not users:
                error_message = "No users found with that email."
        else:
            # **Added validation for empty email field**
            error_message = "Please enter an email to search."

    return render_template('admin/user_search.html', users=users, error_message=error_message)


@app.route('/dashboard/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))  # Redirect to a safe page

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    new_name = request.form.get('name')
    new_mobile_number = request.form.get('mobile_number')

    # **Only update fields that have changed**
    if new_role and new_role != user.role:
        user.role = new_role
    if new_name and new_name != user.name:
        user.name = new_name
    if new_mobile_number and new_mobile_number != user.mobile_number:
        user.mobile_number = new_mobile_number

    # Commit changes to the database if any updates occurred
    db.session.commit()
    flash('User details updated successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    # Mark all notifications as read for the current user
    Notification.query.filter_by(read=False).update({'read': True})
    db.session.commit()
    return '', 204  # No content response


@app.route('/dashboard/all_notifications', methods=['GET'])
@login_required
def all_notifications():
    if current_user.role != 'admin':
        return {'error': 'Unauthorized'}, 403  # Return an error if not admin

    # Get the offset from the query parameters
    offset = int(request.args.get('offset', 0))  # Default to 0 if not provided

    # Fetch notifications starting from the offset
    notifications = Notification.query.order_by(Notification.created_at.desc()).offset(offset).limit(3).all()
    
    # Return notifications in JSON format
    return {
        'notifications': [
            {
                'message': notification.message,
                'created_at': notification.created_at.isoformat()  # Convert datetime to ISO format
            }
            for notification in notifications
    ]
    }
    
    
@app.route('/notification/<int:notification_id>')
@login_required
def notification_details(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    # Mark the notification as read
    notification.read = True
    db.session.commit()

    # Extract the email from the notification message
    email = notification.message.split(" (")[1].rstrip(")")  # Assuming the message format is "New user registered: Name (email@example.com)"

    # Fetch user details from the database using the email
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('User  not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Prepare registration details
    registration_details = {
        'name': user.name,
        'email': user.email,
        'mobile': user.mobile_number,
        'role': user.role,
    }

    return render_template('admin/notification_details.html', notification=notification, registration_details=registration_details)
    

    
# SocketIO event handler for notifications
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')





if __name__ == '__main__':
    socketio.run(app, debug=False)