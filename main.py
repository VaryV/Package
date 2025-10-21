# app.py
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean, inspect
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, configure_mappers
import datetime
import os
import json
import hashlib
import tempfile
import shutil
from groq import Groq
from dotenv import load_dotenv
import pytsk3
import subprocess

# Load environment variables from .env file
load_dotenv()

# Initialize Groq client
client = Groq()

# Define DB models
Base = declarative_base()

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

# Setup DB with check to avoid recreation
engine = create_engine('sqlite:///forensics.db')
inspector = inspect(engine)
if not inspector.has_table('users'):
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
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password_hash=hash_password('adminpass'), is_admin=True)
        session.add(admin)
    user1 = session.query(User).filter_by(username='officer1').first()
    if not user1:
        user1 = User(username='officer1', password_hash=hash_password('pass1'), is_admin=False)
        session.add(user1)
    user2 = session.query(User).filter_by(username='member1').first()
    if not user2:
        user2 = User(username='member1', password_hash=hash_password('pass2'), is_admin=False)
        session.add(user2)
    session.commit()

# Existing backend functions
def file_signature_analysis(file_content: bytes, ext: str) -> str:
    header = file_content[:12]
    ext = ext.lower()
    signatures = {
        '.jpg': b'\xff\xd8\xff',
        '.png': b'\x89PNG\r\n\x1a\n',
        '.pdf': b'%PDF-',
        '.docx': b'PK\x03\x04',
    }
    expected_sig = signatures.get(ext)
    if expected_sig and header.startswith(expected_sig):
        return f"Match: The file extension '{ext}' matches the content signature."
    else:
        return f"Mismatch: The file extension '{ext}' does not match the content signature. Actual header: {header.hex()}"

def carve_jpegs_from_doc(file_content: bytes) -> str:
    data = file_content
    temp_dir = tempfile.mkdtemp()
    carved_files = []
    start_marker = b'\xff\xd8\xff'
    end_marker = b'\xff\xd9'
    pos = 0
    while True:
        start_pos = data.find(start_marker, pos)
        if start_pos == -1:
            break
        end_pos = data.find(end_marker, start_pos)
        if end_pos == -1:
            break
        jpeg_data = data[start_pos:end_pos + 2]
        output_path = os.path.join(temp_dir, f"carved_jpeg_{len(carved_files)}.jpg")
        with open(output_path, 'wb') as out_f:
            out_f.write(jpeg_data)
        carved_files.append(output_path)
        pos = end_pos + 2
    if carved_files:
        return f"Carved {len(carved_files)} JPEG images to {temp_dir}:\n" + "\n".join(carved_files)
    return "No JPEG images found in the file."

def capture_disk_image(source_device: str) -> str:
    CHUNK_SIZE = 1024 * 1024
    temp_dir = tempfile.mkdtemp()
    output_file = os.path.join(temp_dir, "captured_disk.img")
    try:
        with open(source_device, "rb") as src, open(output_file, "wb") as dst:
            total_bytes = 0
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(chunk)
                total_bytes += len(chunk)
                print(f"\r[+] Captured {total_bytes / (1024*1024):.2f} MB", end="")
        print(f"\n[✓] Disk image successfully saved to {output_file}")
        return f"Captured disk image saved to {output_file} (size: {total_bytes} bytes)"
    except PermissionError:
        return "[!] Permission denied. Run this script as administrator/root."
    except FileNotFoundError:
        return f"[!] Source device {source_device} not found."
    except Exception as e:
        return f"[!] Error: {str(e)}"

def recover_deleted_files(file_content: bytes) -> str:
    temp_dir = tempfile.mkdtemp()
    image_path = os.path.join(temp_dir, "disk_image.img")
    with open(image_path, "wb") as f:
        f.write(file_content)
    output_dir = os.path.join(temp_dir, "recovered_files")
    os.makedirs(output_dir, exist_ok=True)
    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img, offset=0)
        recovered_paths = []
        def export_file(f, path):
            if not f.info.meta or f.info.meta.size == 0:
                return
            size = f.info.meta.size
            name = f.info.name.name.decode(errors="ignore")
            safe_name = f"DELETED_{f.info.meta.addr}_{name}"
            out_path = os.path.join(output_dir, safe_name)
            with open(out_path, "wb") as out:
                offset = 0
                while offset < size:
                    available = min(1024 * 1024, size - offset)
                    data = f.read_random(offset, available)
                    if not data:
                        break
                    out.write(data)
                    offset += len(data)
            recovered_paths.append(out_path)
            print(f"[+] Recovered: {out_path} (size={size})")
        def walk_directory(directory, path="/"):
            for f in directory:
                try:
                    name = f.info.name.name.decode(errors="ignore")
                except:
                    continue
                if name in [".", ".."]:
                    continue
                if f.info.meta:
                    if f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                        if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                            export_file(f, path)
                if f.info.meta and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        subdir = f.as_directory()
                        walk_directory(subdir, os.path.join(path, name))
                    except Exception:
                        continue
        root_dir = fs.open_dir(path="/")
        walk_directory(root_dir)
        if recovered_paths:
            return f"Recovered {len(recovered_paths)} files to {output_dir}:\n" + "\n".join(recovered_paths)
        return "No deleted files recovered."
    except Exception as e:
        return f"[!] Error recovering files: {str(e)}"
    finally:
        try:
            os.unlink(image_path)
        except:
            pass

# Tool definitions for LLM
tools = [
    {
        "type": "function",
        "function": {
            "name": "file_signature_analysis",
            "description": "Analyze the file signature to check if the extension matches the actual content type.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "carve_jpegs_from_doc",
            "description": "Carve out embedded JPEG images from a Word document or similar binary file.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "capture_disk_image",
            "description": "Capture a raw disk image from a device (e.g., /dev/sda). Provide the source device path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_device": {
                        "type": "string",
                        "description": "The path to the source device (e.g., /dev/sda or \\\\.\\PhysicalDrive0)."
                    }
                },
                "required": ["source_device"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "recover_deleted_files",
            "description": "Recover deleted files from a disk/partition image using the uploaded file as the image.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

# Function to execute a tool call
def execute_tool(tool_call, file_content: bytes, ext: str):
    func_name = tool_call.function.name
    args = json.loads(tool_call.function.arguments) if tool_call.function.arguments else {}
    print("Tool Called:", func_name, "Args:", args)
    if func_name == "file_signature_analysis":
        result = file_signature_analysis(file_content, ext)
    elif func_name == "carve_jpegs_from_doc":
        result = carve_jpegs_from_doc(file_content)
    elif func_name == "capture_disk_image":
        source_device = args.get("source_device")
        if not source_device:
            result = "Error: source_device parameter is required."
        else:
            result = capture_disk_image(source_device)
    elif func_name == "recover_deleted_files":
        result = recover_deleted_files(file_content)
    else:
        result = "Unknown function."
    print("Tool Result:", result)
    return {
        "role": "tool",
        "tool_call_id": tool_call.id,
        "name": func_name,
        "content": result
    }

# Main function to process query
def process_forensics_query(query: str, file_content: bytes, ext: str):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a computer forensics assistant. For queries about file analysis, "
                "always use the provided tools (file_signature_analysis, carve_jpegs_from_doc, capture_disk_image, recover_deleted_files) "
                "to process the uploaded file or device. For capture_disk_image, use the source_device from the query. "
                "After receiving tool results, summarize them in a concise natural language response. "
                "If no tool is applicable, explain why the query cannot be processed."
            )
        },
        {
            "role": "user",
            "content": f"File uploaded with extension: {ext}\nQuery: {query}"
        }
    ]
    
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.1
        )
        print("Initial Response:", response)
    except Exception as e:
        return f"API Error: {str(e)}"
    
    response_message = response.choices[0].message
    tool_calls = response_message.tool_calls
    
    if tool_calls:
        messages.append(response_message)
        tool_results = []
        for tool_call in tool_calls:
            tool_response = execute_tool(tool_call, file_content, ext)
            messages.append(tool_response)
            tool_results.append(tool_response["content"])
        
        try:
            final_response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            print("Final Response:", final_response)
            content = final_response.choices[0].message.content
            return content if content else tool_results[0]
        except Exception as e:
            return f"Final API Error: {str(e)}"
    else:
        return response_message.content or "Error: No tool called and no direct response provided."

# Streamlit UI
st.title('Computer Forensics Prototype')

session = Session()
init_data(session)

# Initialize session state for active evidence analysis
if 'active_evidence_id' not in st.session_state:
    st.session_state.active_evidence_id = None

if 'chat_messages' not in st.session_state:
    st.session_state.chat_messages = {}

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
        st.session_state.active_evidence_id = None
        st.rerun()
    
    # Check access for cases
    def get_accessible_cases(sess, uid, admin):
        if admin:
            return sess.query(Case).all()
        officer_cases = sess.query(Case).filter(Case.enquiring_officer_id == uid).all()
        team_cases = [tm.case for tm in sess.query(TeamMember).filter_by(user_id=uid).all()]
        accessible = set(officer_cases + team_cases)
        return list(accessible)
    
    accessible_cases = get_accessible_cases(session, user_id, is_admin)
    
    if is_admin:
        st.subheader('Admin Panel')
        with st.expander('Add New Case'):
            title = st.text_input('Case Title')
            description = st.text_area('Description')
            all_users = session.query(User).all()
            officer_options = {u.username: u.id for u in all_users}
            selected_officer_username = st.selectbox('Enquiring Officer', options=list(officer_options.keys()))
            uploaded_files = st.file_uploader('Upload Evidences', accept_multiple_files=True)
            if st.button('Create Case'):
                if title and selected_officer_username:
                    officer_id = officer_options.get(selected_officer_username)
                    if officer_id:
                        officer = session.query(User).filter_by(id=officer_id).first()
                        if officer:
                            new_case = Case(title=title, description=description, enquiring_officer=officer)
                            session.add(new_case)
                            session.commit()
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
                    else:
                        st.error('Invalid selection')
        
        st.subheader('Manage Teams and Assignments')
        all_cases = session.query(Case).all()
        for case in all_cases:
            with st.expander(f'Manage Case: {case.title} (ID: {case.id})'):
                st.write(f'Current Enquiring Officer: {case.enquiring_officer.username if case.enquiring_officer else "None"}')
                selected_new_officer = st.selectbox('Change Officer', options=list(officer_options.keys()), key=f'officer_select_{case.id}')
                if st.button('Update Officer', key=f'update_o_{case.id}'):
                    new_officer_id = officer_options.get(selected_new_officer)
                    if new_officer_id:
                        new_officer = session.query(User).filter_by(id=new_officer_id).first()
                        if new_officer:
                            case.enquiring_officer = new_officer
                            session.commit()
                            st.success('Updated')
                            st.rerun()
                member_options = {u.username: u.id for u in all_users if u.id != case.enquiring_officer_id}
                selected_member_username = st.selectbox('Add Team Member', options=list(member_options.keys()), key=f'tm_select_{case.id}')
                if st.button('Add Member', key=f'add_tm_{case.id}'):
                    tm_user_id = member_options.get(selected_member_username)
                    if tm_user_id:
                        tm_user = session.query(User).filter_by(id=tm_user_id).first()
                        if tm_user:
                            existing = session.query(TeamMember).filter_by(case_id=case.id, user_id=tm_user.id).first()
                            if not existing:
                                new_tm = TeamMember(case_id=case.id, user_id=tm_user.id)
                                session.add(new_tm)
                                session.commit()
                                st.success('Added')
                                st.rerun()
                            else:
                                st.info('Already a member')
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
                if st.button('View Details', key=f'view_{case.id}'):
                    log_access(session, user_id, case.id, operation='view_case')
                    st.write('Case details viewed (logged).')
                evidences = case.evidences
                if evidences:
                    st.write('Evidences:')
                    for evidence in evidences:
                        st.write(f'- {evidence.file_name} (Uploaded: {evidence.uploaded_at})')
                        metadata = json.loads(evidence.evidence_metadata) if evidence.evidence_metadata else {}
                        st.write(f'  Metadata: {metadata}')
                        
                        # Button to start/stop analysis
                        col1, col2 = st.columns([1, 4])
                        with col1:
                            if st.button(f'Analyze', key=f'analyze_{evidence.id}'):
                                if st.session_state.active_evidence_id == evidence.id:
                                    # Close the chat
                                    st.session_state.active_evidence_id = None
                                else:
                                    # Open the chat for this evidence
                                    st.session_state.active_evidence_id = evidence.id
                                    log_access(session, user_id, case.id, evidence.id, 'analyze_evidence')
                                st.rerun()
                        
                        # Display chat interface if this evidence is active
                        if st.session_state.active_evidence_id == evidence.id:
                            if evidence.id not in st.session_state.chat_messages:
                                st.session_state.chat_messages[evidence.id] = []
                            
                            st.markdown(f"**Chat for {evidence.file_name}**")
                            
                            # Display chat history
                            for message in st.session_state.chat_messages[evidence.id]:
                                with st.chat_message(message["role"]):
                                    st.markdown(message["content"])
                            
                            # Chat input
                            query = st.chat_input(f"Ask about {evidence.file_name}", key=f"chat_input_{evidence.id}")
                            if query:
                                # Add user message
                                with st.chat_message("user"):
                                    st.markdown(query)
                                st.session_state.chat_messages[evidence.id].append({"role": "user", "content": query})
                                
                                # Process the query
                                file_path = evidence.file_path
                                with open(file_path, 'rb') as f:
                                    file_content = f.read()
                                ext = os.path.splitext(evidence.file_name)[1]
                                
                                with st.spinner("Analyzing..."):
                                    result = process_forensics_query(query, file_content, ext)
                                
                                # Add assistant response
                                with st.chat_message("assistant"):
                                    st.markdown(result)
                                st.session_state.chat_messages[evidence.id].append({"role": "assistant", "content": result})
                                
                                st.rerun()
                else:
                    st.write('No evidences.')
                team_members = [tm.member.username for tm in case.team_members]
                st.write(f'Team Members: {", ".join(team_members)}')
                if is_admin or (case.enquiring_officer_id == user_id):
                    st.write('Access Logs:')
                    logs = session.query(AccessLog).filter_by(case_id=case.id).all()
                    for log in logs:
                        ev_name = log.evidence.file_name if log.evidence else 'Case Level'
                        st.write(f'- User {log.user.username}: {log.operation} on {ev_name} at {log.timestamp}')

    if is_admin:
        st.subheader('All Access Logs')
        all_logs = session.query(AccessLog).all()
        for log in all_logs:
            ev_name = log.evidence.file_name if log.evidence else 'Case Level'
            st.write(f'User {log.user.username} - Case {log.case.id}: {log.operation} on {ev_name} at {log.timestamp}')

session.close()