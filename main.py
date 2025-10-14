# app.py
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, configure_mappers
import datetime
import os
import json
import hashlib

Base = declarative_base()

# Define DB models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)
    
    # Relationships
    assigned_cases = relationship('Case', back_populates='enquiring_officer')
    team_memberships = relationship('TeamMember', back_populates='member')
    access_logs = relationship('AccessLog', back_populates='user')

class Case(Base):
    __tablename__ = 'cases'
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    enquiring_officer_id = Column(Integer, ForeignKey('users.id'))
    enquiring_officer = relationship('User', back_populates='assigned_cases')
    evidences = relationship('Evidence', back_populates='case', cascade='all, delete-orphan')
    team_members = relationship('TeamMember', back_populates='case', cascade='all, delete-orphan')
    access_logs = relationship('AccessLog', back_populates='case')

class TeamMember(Base):
    __tablename__ = 'team_members'
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Relationships
    case = relationship('Case', back_populates='team_members')
    member = relationship('User', back_populates='team_memberships')

class Evidence(Base):
    __tablename__ = 'evidences'
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    file_name = Column(String(100), nullable=False)
    file_path = Column(String(255), nullable=False)
    evidence_metadata = Column(Text)  # JSON string for additional metadata
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    case = relationship('Case', back_populates='evidences')
    access_logs = relationship('AccessLog', back_populates='evidence')

class AccessLog(Base):
    __tablename__ = 'access_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    evidence_id = Column(Integer, ForeignKey('evidences.id'), nullable=True)  # Null if case-level access
    operation = Column(String(50), nullable=False)  # e.g., 'view_case', 'download_evidence'
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='access_logs')
    case = relationship('Case', back_populates='access_logs')
    evidence = relationship('Evidence', back_populates='access_logs')

# Force configuration of mappers after all classes defined
configure_mappers()

# Setup DB
engine = create_engine('sqlite:///forensics.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    return stored_hash == hashlib.sha256(password.encode()).hexdigest()

def log_access(session, user_id, case_id, evidence_id=None, operation='view'):
    log = AccessLog(user_id=user_id, case_id=case_id, evidence_id=evidence_id, operation=operation)
    session.add(log)
    session.commit()

def init_data(session):
    # Create admin if not exists
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password_hash=hash_password('adminpass'), is_admin=True)
        session.add(admin)
    
    # Create sample users
    user1 = session.query(User).filter_by(username='officer1').first()
    if not user1:
        user1 = User(username='officer1', password_hash=hash_password('pass1'), is_admin=False)
        session.add(user1)
    
    user2 = session.query(User).filter_by(username='member1').first()
    if not user2:
        user2 = User(username='member1', password_hash=hash_password('pass2'), is_admin=False)
        session.add(user2)
    
    session.commit()

# Streamlit UI
st.title('Computer Forensics Prototype')

session = Session()
init_data(session)

# Login
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
    st.session_state.is_admin = False

if not st.session_state.user_id:
    st.subheader('Login')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        user = session.query(User).filter_by(username=username).first()
        if user and verify_password(user.password_hash, password):
            st.session_state.user_id = user.id
            st.session_state.is_admin = user.is_admin
            st.success('Logged in!')
            st.rerun()
        else:
            st.error('Invalid credentials')
else:
    user_id = st.session_state.user_id
    is_admin = st.session_state.is_admin
    user = session.query(User).filter_by(id=user_id).first()
    st.sidebar.write(f'Logged in as: {user.username} {"(Admin)" if is_admin else ""}')
    if st.sidebar.button('Logout'):
        st.session_state.user_id = None
        st.session_state.is_admin = False
        st.rerun()
    
    # Check access for cases
    def get_accessible_cases(sess, uid, admin):
        if admin:
            return sess.query(Case).all()
        # Get cases where user is enquiring officer or team member
        officer_cases = sess.query(Case).filter(Case.enquiring_officer_id == uid).all()
        team_cases = [tm.case for tm in sess.query(TeamMember).filter_by(user_id=uid).all()]
        accessible = set(officer_cases + team_cases)
        return list(accessible)
    
    accessible_cases = get_accessible_cases(session, user_id, is_admin)
    
    if is_admin:
        st.subheader('Admin Panel')
        
        # Add new case
        with st.expander('Add New Case'):
            title = st.text_input('Case Title')
            description = st.text_area('Description')
            enquiring_officer_username = st.text_input('Enquiring Officer Username')
            uploaded_files = st.file_uploader('Upload Evidences', accept_multiple_files=True)
            if st.button('Create Case'):
                if title and enquiring_officer_username:
                    officer = session.query(User).filter_by(username=enquiring_officer_username).first()
                    if officer:
                        new_case = Case(title=title, description=description, enquiring_officer=officer)
                        session.add(new_case)
                        session.commit()
                        
                        # Handle evidence uploads
                        evidence_dir = 'evidences'
                        os.makedirs(evidence_dir, exist_ok=True)
                        for uploaded_file in uploaded_files:
                            file_path = os.path.join(evidence_dir, f"case_{new_case.id}_{uploaded_file.name}")
                            with open(file_path, "wb") as f:
                                f.write(uploaded_file.getbuffer())
                            metadata = {'original_name': uploaded_file.name, 'size': uploaded_file.size}
                            evidence = Evidence(case_id=new_case.id, file_name=uploaded_file.name, file_path=file_path, evidence_metadata=json.dumps(metadata))
                            session.add(evidence)
                        session.commit()
                        st.success('Case created!')
                    else:
                        st.error('Officer not found')
        
        # Manage teams and assignments
        st.subheader('Manage Teams and Assignments')
        all_cases = session.query(Case).all()
        for case in all_cases:
            with st.expander(f'Manage Case: {case.title} (ID: {case.id})'):
                # Current officer
                st.write(f'Current Enquiring Officer: {case.enquiring_officer.username if case.enquiring_officer else "None"}')
                new_officer_username = st.text_input(f'Change Officer for {case.title}', key=f'officer_{case.id}')
                if st.button('Update Officer', key=f'update_o_{case.id}'):
                    new_officer = session.query(User).filter_by(username=new_officer_username).first()
                    if new_officer:
                        case.enquiring_officer = new_officer
                        session.commit()
                        st.success('Updated')
                
                # Add team member
                team_member_username = st.text_input(f'Add Team Member to {case.title}', key=f'tm_{case.id}')
                if st.button('Add Member', key=f'add_tm_{case.id}'):
                    tm_user = session.query(User).filter_by(username=team_member_username).first()
                    if tm_user:
                        existing = session.query(TeamMember).filter_by(case_id=case.id, user_id=tm_user.id).first()
                        if not existing:
                            new_tm = TeamMember(case_id=case.id, user_id=tm_user.id)
                            session.add(new_tm)
                            session.commit()
                            st.success('Added')
                        else:
                            st.info('Already a member')
                
                # List team members
                team_members = [tm.member.username for tm in case.team_members]
                st.write(f'Team Members: {", ".join(team_members)}')
    
    # User view: My Cases
    st.subheader('My Accessible Cases')
    if not accessible_cases:
        st.info('No cases accessible.')
    else:
        for case in accessible_cases:
            with st.expander(f'Case: {case.title} (ID: {case.id})'):
                st.write(f'Description: {case.description}')
                st.write(f'Enquiring Officer: {case.enquiring_officer.username if case.enquiring_officer else "N/A"}')
                
                # Log case view
                if st.button('View Details', key=f'view_{case.id}'):
                    log_access(session, user_id, case.id, operation='view_case')
                    st.write('Case details viewed (logged).')
                
                # Evidences
                evidences = case.evidences
                if evidences:
                    st.write('Evidences:')
                    for evidence in evidences:
                        st.write(f'- {evidence.file_name} (Uploaded: {evidence.uploaded_at})')
                        metadata = json.loads(evidence.evidence_metadata) if evidence.evidence_metadata else {}
                        st.write(f'  Metadata: {metadata}')
                        if st.button(f'Download {evidence.file_name}', key=f'dl_{evidence.id}'):
                            log_access(session, user_id, case.id, evidence.id, 'download_evidence')
                            with open(evidence.file_path, 'rb') as f:
                                st.download_button(f'Download {evidence.file_name}', f, file_name=evidence.file_name)
                else:
                    st.write('No evidences.')
                
                # Team members (view only)
                team_members = [tm.member.username for tm in case.team_members]
                st.write(f'Team Members: {", ".join(team_members)}')
                
                # Access logs for admin or officer
                if is_admin or (case.enquiring_officer_id == user_id):
                    st.write('Access Logs:')
                    logs = session.query(AccessLog).filter_by(case_id=case.id).all()
                    for log in logs:
                        ev_name = log.evidence.file_name if log.evidence else 'Case Level'
                        st.write(f'- User {log.user.username}: {log.operation} on {ev_name} at {log.timestamp}')

    # Admin: All access logs
    if is_admin:
        st.subheader('All Access Logs')
        all_logs = session.query(AccessLog).all()
        for log in all_logs:
            ev_name = log.evidence.file_name if log.evidence else 'Case Level'
            st.write(f'User {log.user.username} - Case {log.case.id}: {log.operation} on {ev_name} at {log.timestamp}')

session.close()