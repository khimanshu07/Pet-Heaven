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

    # Relationship with certifications
    certifications = db.relationship('Certification', back_populates='trainer', lazy=True)

    # Relationship with services
    services = db.relationship('Service', secondary='trainer_services', back_populates='trainers')

    def __repr__(self):
        return f'<Trainer {self.id} for User {self.user.name}>'

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=True)

    # Relationship with trainers
    trainers = db.relationship('Trainer', secondary='trainer_services', back_populates='services')

    def __repr__(self):
        return f'<Service {self.name}>'

class TrainerService(db.Model):
    __tablename__ = 'trainer_services'
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)

    trainer = db.relationship('Trainer', back_populates='trainer_services')
    service = db.relationship('Service', back_populates='trainer_services')

    def __repr__(self):
        return f'<TrainerService trainer_id={self.trainer_id} service_id={self.service_id} price={self.price}>'

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    image_path = db.Column(db.String(255), nullable=True)

    # Relationship with trainer
    trainer = db.relationship('Trainer', back_populates='certifications')

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