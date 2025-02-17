from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# Enum for status fields (SQLite compatible)
class VerificationStatus:
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=True)
    role = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_picture = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<User {self.name}>'

class Trainer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='trainers')
    verified = db.Column(db.String(50), default='Pending', nullable=False)
    experience = db.Column(db.Integer, nullable=True)
    specialization = db.Column(db.String(100), nullable=True)
    availability_schedule = db.Column(db.JSON, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    ratings = db.Column(db.Float, nullable=True)
    aadhaar_image_path = db.Column(db.String(255), nullable=True)
    pan_card_image_path = db.Column(db.String(255), nullable=True)

    # Relationship with certifications (Changed backref name to 'trainer_certifications')
    certifications = db.relationship('Certification', backref='trainer_certifications', lazy=True)

    # Relationship with services
    services = db.relationship('Service', secondary='trainer_services', backref='trainers')

    def __repr__(self):
        return f'<Trainer {self.id} for User {self.user.name}>'

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image=db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<Service {self.name}>'
    
class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.String(100), nullable=False)
    time = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image=db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<Event {self.name}>'

class TrainerService(db.Model):
    __tablename__ = 'trainer_services'
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)

    trainer = db.relationship('Trainer', backref=db.backref('trainer_services', lazy=True))
    service = db.relationship('Service', backref=db.backref('trainer_services', lazy=True))

    def __repr__(self):
        return f'<TrainerService trainer_id={self.trainer_id} service_id={self.service_id} price={self.price}>'

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    image_path = db.Column(db.String(255), nullable=True)

    # Backref to trainer (changed backref name to 'trainer_certifications')
    trainer = db.relationship('Trainer', backref=db.backref('trainer_certifications', lazy=True))

    def __repr__(self):
        return f'<Certification {self.name} for Trainer {self.trainer_id}>'

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='admins')

    def __repr__(self):
        return f'<Admin {self.id} for User {self.user.name}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='notifications')

    def __repr__(self):
        return f'<Notification {self.id} for User {self.user.name}>'
