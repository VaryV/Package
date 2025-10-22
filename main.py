# # app.py
# import streamlit as st
# from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean, inspect
# from sqlalchemy.orm import declarative_base, sessionmaker, relationship, configure_mappers
# import datetime
# import os
# import json
# import hashlib
# import tempfile
# import shutil
# from groq import Groq
# from dotenv import load_dotenv
# import pytsk3
# import subprocess

# # Load environment variables from .env file
# load_dotenv()

# # Initialize Groq client
# client = Groq()

# # Define DB models
# Base = declarative_base()

# class User(Base):
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True)
#     username = Column(String(50), unique=True, nullable=False)
#     password_hash = Column(String(128), nullable=False)
#     is_admin = Column(Boolean, default=False)
    
#     # Relationships
#     assigned_cases = relationship('Case', back_populates='enquiring_officer')
#     team_memberships = relationship('TeamMember', back_populates='member')
#     access_logs = relationship('AccessLog', back_populates='user')

# class Case(Base):
#     __tablename__ = 'cases'
#     id = Column(Integer, primary_key=True)
#     title = Column(String(100), nullable=False)
#     description = Column(Text)
#     created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
#     # Relationships
#     enquiring_officer_id = Column(Integer, ForeignKey('users.id'))
#     enquiring_officer = relationship('User', back_populates='assigned_cases')
#     evidences = relationship('Evidence', back_populates='case', cascade='all, delete-orphan')
#     team_members = relationship('TeamMember', back_populates='case', cascade='all, delete-orphan')
#     access_logs = relationship('AccessLog', back_populates='case')

# class TeamMember(Base):
#     __tablename__ = 'team_members'
#     id = Column(Integer, primary_key=True)
#     case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
#     # Relationships
#     case = relationship('Case', back_populates='team_members')
#     member = relationship('User', back_populates='team_memberships')

# class Evidence(Base):
#     __tablename__ = 'evidences'
#     id = Column(Integer, primary_key=True)
#     case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
#     file_name = Column(String(100), nullable=False)
#     file_path = Column(String(255), nullable=False)
#     evidence_metadata = Column(Text)  # JSON string for additional metadata
#     uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    
#     # Relationships
#     case = relationship('Case', back_populates='evidences')
#     access_logs = relationship('AccessLog', back_populates='evidence')

# class AccessLog(Base):
#     __tablename__ = 'access_logs'
#     id = Column(Integer, primary_key=True)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
#     case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
#     evidence_id = Column(Integer, ForeignKey('evidences.id'), nullable=True)  # Null if case-level access
#     operation = Column(String(50), nullable=False)  # e.g., 'view_case', 'analyze_evidence'
#     timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
#     # NEW FIELDS for Chain of Custody
#     query = Column(Text, nullable=True)  # User's natural language query
#     tool_called = Column(String(100), nullable=True)  # Name of the tool that was called
#     tool_arguments = Column(Text, nullable=True)  # JSON string of tool arguments
#     tool_result = Column(Text, nullable=True)  # Result returned by the tool
#     llm_response = Column(Text, nullable=True)  # Final LLM response to user
    
#     # Relationships
#     user = relationship('User', back_populates='access_logs')
#     case = relationship('Case', back_populates='access_logs')
#     evidence = relationship('Evidence', back_populates='access_logs')

# # Force configuration of mappers after all classes defined
# configure_mappers()

# # Setup DB with check to avoid recreation
# engine = create_engine('sqlite:///forensics.db')
# inspector = inspect(engine)

# # Create all tables if database is new
# if not inspector.has_table('users'):
#     Base.metadata.create_all(engine)
#     print("✓ Database created with all tables")
# else:
#     # For existing database, try to add new columns if they don't exist
#     try:
#         # This will add any missing columns/tables
#         Base.metadata.create_all(engine)
        
#         # Verify and add missing columns to access_logs if needed
#         with engine.connect() as conn:
#             # Check if new columns exist in access_logs
#             result = conn.execute("PRAGMA table_info(access_logs)").fetchall()
#             existing_columns = [row[1] for row in result]
            
#             new_columns = {
#                 'query': 'TEXT',
#                 'tool_called': 'VARCHAR(100)',
#                 'tool_arguments': 'TEXT',
#                 'tool_result': 'TEXT',
#                 'llm_response': 'TEXT'
#             }
            
#             for col_name, col_type in new_columns.items():
#                 if col_name not in existing_columns:
#                     conn.execute(f"ALTER TABLE access_logs ADD COLUMN {col_name} {col_type}")
#                     conn.commit()
#                     print(f"✓ Added column '{col_name}' to access_logs table")
#     except Exception as e:
#         print(f"Note: Schema update attempt: {e}")

# Session = sessionmaker(bind=engine)

# # Helper functions
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

# def verify_password(stored_hash, password):
#     return stored_hash == hashlib.sha256(password.encode()).hexdigest()

# def log_access(session, user_id, case_id, evidence_id=None, operation='view', 
#                query=None, tool_called=None, tool_arguments=None, tool_result=None, llm_response=None):
#     """Enhanced logging function with chain of custody details"""
#     log = AccessLog(
#         user_id=user_id, 
#         case_id=case_id, 
#         evidence_id=evidence_id, 
#         operation=operation,
#         query=query,
#         tool_called=tool_called,
#         tool_arguments=tool_arguments,
#         tool_result=tool_result,
#         llm_response=llm_response
#     )
#     session.add(log)
#     session.commit()
#     return log

# def init_data(session):
#     """Initialize default users if they don't exist"""
#     # Create admin user
#     admin = session.query(User).filter_by(username='admin').first()
#     if not admin:
#         admin = User(username='admin', password_hash=hash_password('adminpass'), is_admin=True)
#         session.add(admin)
#         print("✓ Created admin user (username: admin, password: adminpass)")
    
#     # Create officer1 user
#     user1 = session.query(User).filter_by(username='officer1').first()
#     if not user1:
#         user1 = User(username='officer1', password_hash=hash_password('pass1'), is_admin=False)
#         session.add(user1)
#         print("✓ Created officer1 user (username: officer1, password: pass1)")
    
#     # Create member1 user
#     user2 = session.query(User).filter_by(username='member1').first()
#     if not user2:
#         user2 = User(username='member1', password_hash=hash_password('pass2'), is_admin=False)
#         session.add(user2)
#         print("✓ Created member1 user (username: member1, password: pass2)")
    
#     session.commit()
    
#     # Display summary
#     total_users = session.query(User).count()
#     print(f"✓ Database initialized with {total_users} users")

# # Existing backend functions
# def file_signature_analysis(file_content: bytes, ext: str) -> str:
#     header = file_content[:12]
#     ext = ext.lower()
#     signatures = {
#         '.jpg': b'\xff\xd8\xff',
#         '.png': b'\x89PNG\r\n\x1a\n',
#         '.pdf': b'%PDF-',
#         '.docx': b'PK\x03\x04',
#     }
#     expected_sig = signatures.get(ext)
#     if expected_sig and header.startswith(expected_sig):
#         return f"Match: The file extension '{ext}' matches the content signature."
#     else:
#         return f"Mismatch: The file extension '{ext}' does not match the content signature. Actual header: {header.hex()}"

# def carve_jpegs_from_doc(file_content: bytes) -> str:
#     data = file_content
#     temp_dir = tempfile.mkdtemp()
#     carved_files = []
#     start_marker = b'\xff\xd8\xff'
#     end_marker = b'\xff\xd9'
#     pos = 0
#     while True:
#         start_pos = data.find(start_marker, pos)
#         if start_pos == -1:
#             break
#         end_pos = data.find(end_marker, start_pos)
#         if end_pos == -1:
#             break
#         jpeg_data = data[start_pos:end_pos + 2]
#         output_path = os.path.join(temp_dir, f"carved_jpeg_{len(carved_files)}.jpg")
#         with open(output_path, 'wb') as out_f:
#             out_f.write(jpeg_data)
#         carved_files.append(output_path)
#         pos = end_pos + 2
#     if carved_files:
#         return f"Carved {len(carved_files)} JPEG images to {temp_dir}:\n" + "\n".join(carved_files)
#     return "No JPEG images found in the file."

# def capture_disk_image(source_device: str) -> str:
#     CHUNK_SIZE = 1024 * 1024
#     temp_dir = tempfile.mkdtemp()
#     output_file = os.path.join(temp_dir, "captured_disk.img")
#     try:
#         with open(source_device, "rb") as src, open(output_file, "wb") as dst:
#             total_bytes = 0
#             while True:
#                 chunk = src.read(CHUNK_SIZE)
#                 if not chunk:
#                     break
#                 dst.write(chunk)
#                 total_bytes += len(chunk)
#                 print(f"\r[+] Captured {total_bytes / (1024*1024):.2f} MB", end="")
#         print(f"\n[✓] Disk image successfully saved to {output_file}")
#         return f"Captured disk image saved to {output_file} (size: {total_bytes} bytes)"
#     except PermissionError:
#         return "[!] Permission denied. Run this script as administrator/root."
#     except FileNotFoundError:
#         return f"[!] Source device {source_device} not found."
#     except Exception as e:
#         return f"[!] Error: {str(e)}"

# def recover_deleted_files(file_content: bytes) -> str:
#     temp_dir = tempfile.mkdtemp()
#     image_path = os.path.join(temp_dir, "disk_image.img")
#     with open(image_path, "wb") as f:
#         f.write(file_content)
#     output_dir = os.path.join(temp_dir, "recovered_files")
#     os.makedirs(output_dir, exist_ok=True)
#     try:
#         img = pytsk3.Img_Info(image_path)
#         fs = pytsk3.FS_Info(img, offset=0)
#         recovered_paths = []
#         def export_file(f, path):
#             if not f.info.meta or f.info.meta.size == 0:
#                 return
#             size = f.info.meta.size
#             name = f.info.name.name.decode(errors="ignore")
#             safe_name = f"DELETED_{f.info.meta.addr}_{name}"
#             out_path = os.path.join(output_dir, safe_name)
#             with open(out_path, "wb") as out:
#                 offset = 0
#                 while offset < size:
#                     available = min(1024 * 1024, size - offset)
#                     data = f.read_random(offset, available)
#                     if not data:
#                         break
#                     out.write(data)
#                     offset += len(data)
#             recovered_paths.append(out_path)
#             print(f"[+] Recovered: {out_path} (size={size})")
#         def walk_directory(directory, path="/"):
#             for f in directory:
#                 try:
#                     name = f.info.name.name.decode(errors="ignore")
#                 except:
#                     continue
#                 if name in [".", ".."]:
#                     continue
#                 if f.info.meta:
#                     if f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
#                         if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
#                             export_file(f, path)
#                 if f.info.meta and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
#                     try:
#                         subdir = f.as_directory()
#                         walk_directory(subdir, os.path.join(path, name))
#                     except Exception:
#                         continue
#         root_dir = fs.open_dir(path="/")
#         walk_directory(root_dir)
#         if recovered_paths:
#             return f"Recovered {len(recovered_paths)} files to {output_dir}:\n" + "\n".join(recovered_paths)
#         return "No deleted files recovered."
#     except Exception as e:
#         return f"[!] Error recovering files: {str(e)}"
#     finally:
#         try:
#             os.unlink(image_path)
#         except:
#             pass

# # Tool definitions for LLM
# tools = [
#     {
#         "type": "function",
#         "function": {
#             "name": "file_signature_analysis",
#             "description": "Analyze the file signature to check if the extension matches the actual content type.",
#             "parameters": {
#                 "type": "object",
#                 "properties": {},
#                 "required": []
#             }
#         }
#     },
#     {
#         "type": "function",
#         "function": {
#             "name": "carve_jpegs_from_doc",
#             "description": "Carve out embedded JPEG images from a Word document or similar binary file.",
#             "parameters": {
#                 "type": "object",
#                 "properties": {},
#                 "required": []
#             }
#         }
#     },
#     {
#         "type": "function",
#         "function": {
#             "name": "capture_disk_image",
#             "description": "Capture a raw disk image from a device (e.g., /dev/sda). Provide the source device path.",
#             "parameters": {
#                 "type": "object",
#                 "properties": {
#                     "source_device": {
#                         "type": "string",
#                         "description": "The path to the source device (e.g., /dev/sda or \\\\.\\PhysicalDrive0)."
#                     }
#                 },
#                 "required": ["source_device"]
#             }
#         }
#     },
#     {
#         "type": "function",
#         "function": {
#             "name": "recover_deleted_files",
#             "description": "Recover deleted files from a disk/partition image using the uploaded file as the image.",
#             "parameters": {
#                 "type": "object",
#                 "properties": {},
#                 "required": []
#             }
#         }
#     }
# ]

# # Function to execute a tool call
# def execute_tool(tool_call, file_content: bytes, ext: str):
#     func_name = tool_call.function.name
#     args = json.loads(tool_call.function.arguments) if tool_call.function.arguments else {}
#     print("Tool Called:", func_name, "Args:", args)
#     if func_name == "file_signature_analysis":
#         result = file_signature_analysis(file_content, ext)
#     elif func_name == "carve_jpegs_from_doc":
#         result = carve_jpegs_from_doc(file_content)
#     elif func_name == "capture_disk_image":
#         source_device = args.get("source_device")
#         if not source_device:
#             result = "Error: source_device parameter is required."
#         else:
#             result = capture_disk_image(source_device)
#     elif func_name == "recover_deleted_files":
#         result = recover_deleted_files(file_content)
#     else:
#         result = "Unknown function."
#     print("Tool Result:", result)
#     return {
#         "role": "tool",
#         "tool_call_id": tool_call.id,
#         "name": func_name,
#         "content": result
#     }, func_name, args, result

# # Main function to process query - now returns detailed info for logging
# def process_forensics_query(query: str, file_content: bytes, ext: str):
#     messages = [
#         {
#             "role": "system",
#             "content": (
#                 "You are a computer forensics assistant. For queries about file analysis, "
#                 "always use the provided tools (file_signature_analysis, carve_jpegs_from_doc, capture_disk_image, recover_deleted_files) "
#                 "to process the uploaded file or device. For capture_disk_image, use the source_device from the query. "
#                 "After receiving tool results, summarize them in a concise natural language response. "
#                 "If no tool is applicable, explain why the query cannot be processed."
#             )
#         },
#         {
#             "role": "user",
#             "content": f"File uploaded with extension: {ext}\nQuery: {query}"
#         }
#     ]
    
#     tool_info = {
#         'tool_called': None,
#         'tool_arguments': None,
#         'tool_result': None
#     }
    
#     try:
#         response = client.chat.completions.create(
#             model="llama-3.1-8b-instant",
#             messages=messages,
#             tools=tools,
#             tool_choice="auto",
#             temperature=0.1
#         )
#         print("Initial Response:", response)
#     except Exception as e:
#         return f"API Error: {str(e)}", tool_info
    
#     response_message = response.choices[0].message
#     tool_calls = response_message.tool_calls
    
#     if tool_calls:
#         messages.append(response_message)
#         tool_results = []
#         for tool_call in tool_calls:
#             tool_response, func_name, args, result = execute_tool(tool_call, file_content, ext)
#             messages.append(tool_response)
#             tool_results.append(tool_response["content"])
            
#             # Store tool info for logging (last tool if multiple)
#             tool_info['tool_called'] = func_name
#             tool_info['tool_arguments'] = json.dumps(args)
#             tool_info['tool_result'] = result
        
#         try:
#             final_response = client.chat.completions.create(
#                 model="llama-3.1-8b-instant",
#                 messages=messages,
#                 tools=tools,
#                 tool_choice="auto"
#             )
#             print("Final Response:", final_response)
#             content = final_response.choices[0].message.content
#             return (content if content else tool_results[0]), tool_info
#         except Exception as e:
#             return f"Final API Error: {str(e)}", tool_info
#     else:
#         return (response_message.content or "Error: No tool called and no direct response provided."), tool_info

# def load_chat_history(session, evidence_id, current_user_id):
#     """Load chat history from access logs for a specific evidence file"""
#     logs = session.query(AccessLog).filter(
#         AccessLog.evidence_id == evidence_id,
#         AccessLog.operation == 'analyze_evidence',
#         AccessLog.query.isnot(None)
#     ).order_by(AccessLog.timestamp).all()
    
#     chat_history = []
#     for log in logs:
#         # Add user query
#         chat_history.append({
#             "role": "user",
#             "content": log.query,
#             "timestamp": log.timestamp,
#             "user": log.user.username
#         })
        
#         # Add assistant response
#         if log.llm_response:
#             chat_history.append({
#                 "role": "assistant",
#                 "content": log.llm_response,
#                 "timestamp": log.timestamp,
#                 "tool_called": log.tool_called
#             })
    
#     return chat_history

# # Streamlit UI
# st.title('Computer Forensics Prototype - Chain of Custody System')

# session = Session()
# init_data(session)

# # Initialize session state for active evidence analysis
# if 'active_evidence_id' not in st.session_state:
#     st.session_state.active_evidence_id = None

# if 'chat_messages' not in st.session_state:
#     st.session_state.chat_messages = {}

# if 'chat_loaded' not in st.session_state:
#     st.session_state.chat_loaded = {}

# # Login
# if 'user_id' not in st.session_state:
#     st.session_state.user_id = None
#     st.session_state.is_admin = False

# if not st.session_state.user_id:
#     st.subheader('Login')
#     username = st.text_input('Username')
#     password = st.text_input('Password', type='password')
#     if st.button('Login'):
#         user = session.query(User).filter_by(username=username).first()
#         if user and verify_password(user.password_hash, password):
#             st.session_state.user_id = user.id
#             st.session_state.is_admin = user.is_admin
#             st.success('Logged in!')
#             st.rerun()
#         else:
#             st.error('Invalid credentials')
# else:
#     user_id = st.session_state.user_id
#     is_admin = st.session_state.is_admin
#     user = session.query(User).filter_by(id=user_id).first()
#     st.sidebar.write(f'Logged in as: {user.username} {"(Admin)" if is_admin else ""}')
#     if st.sidebar.button('Logout'):
#         st.session_state.user_id = None
#         st.session_state.is_admin = False
#         st.session_state.active_evidence_id = None
#         st.session_state.chat_messages = {}
#         st.session_state.chat_loaded = {}
#         st.rerun()
    
#     # Check access for cases
#     def get_accessible_cases(sess, uid, admin):
#         if admin:
#             return sess.query(Case).all()
#         officer_cases = sess.query(Case).filter(Case.enquiring_officer_id == uid).all()
#         team_cases = [tm.case for tm in sess.query(TeamMember).filter_by(user_id=uid).all()]
#         accessible = set(officer_cases + team_cases)
#         return list(accessible)
    
#     accessible_cases = get_accessible_cases(session, user_id, is_admin)
    
#     if is_admin:
#         st.subheader('Admin Panel')
#         with st.expander('Add New Case'):
#             title = st.text_input('Case Title')
#             description = st.text_area('Description')
#             all_users = session.query(User).all()
#             officer_options = {u.username: u.id for u in all_users}
#             selected_officer_username = st.selectbox('Enquiring Officer', options=list(officer_options.keys()))
#             uploaded_files = st.file_uploader('Upload Evidences', accept_multiple_files=True)
#             if st.button('Create Case'):
#                 if title and selected_officer_username:
#                     officer_id = officer_options.get(selected_officer_username)
#                     if officer_id:
#                         officer = session.query(User).filter_by(id=officer_id).first()
#                         if officer:
#                             new_case = Case(title=title, description=description, enquiring_officer=officer)
#                             session.add(new_case)
#                             session.commit()
#                             evidence_dir = 'evidences'
#                             os.makedirs(evidence_dir, exist_ok=True)
#                             for uploaded_file in uploaded_files:
#                                 file_path = os.path.join(evidence_dir, f"case_{new_case.id}_{uploaded_file.name}")
#                                 with open(file_path, "wb") as f:
#                                     f.write(uploaded_file.getbuffer())
#                                 metadata = {'original_name': uploaded_file.name, 'size': uploaded_file.size}
#                                 evidence = Evidence(case_id=new_case.id, file_name=uploaded_file.name, file_path=file_path, evidence_metadata=json.dumps(metadata))
#                                 session.add(evidence)
#                             session.commit()
#                             st.success('Case created!')
#                         else:
#                             st.error('Officer not found')
#                     else:
#                         st.error('Invalid selection')
        
#         st.subheader('Manage Teams and Assignments')
#         all_cases = session.query(Case).all()
#         for case in all_cases:
#             with st.expander(f'Manage Case: {case.title} (ID: {case.id})'):
#                 st.write(f'Current Enquiring Officer: {case.enquiring_officer.username if case.enquiring_officer else "None"}')
#                 selected_new_officer = st.selectbox('Change Officer', options=list(officer_options.keys()), key=f'officer_select_{case.id}')
#                 if st.button('Update Officer', key=f'update_o_{case.id}'):
#                     new_officer_id = officer_options.get(selected_new_officer)
#                     if new_officer_id:
#                         new_officer = session.query(User).filter_by(id=new_officer_id).first()
#                         if new_officer:
#                             case.enquiring_officer = new_officer
#                             session.commit()
#                             st.success('Updated')
#                             st.rerun()
#                 member_options = {u.username: u.id for u in all_users if u.id != case.enquiring_officer_id}
#                 selected_member_username = st.selectbox('Add Team Member', options=list(member_options.keys()), key=f'tm_select_{case.id}')
#                 if st.button('Add Member', key=f'add_tm_{case.id}'):
#                     tm_user_id = member_options.get(selected_member_username)
#                     if tm_user_id:
#                         tm_user = session.query(User).filter_by(id=tm_user_id).first()
#                         if tm_user:
#                             existing = session.query(TeamMember).filter_by(case_id=case.id, user_id=tm_user.id).first()
#                             if not existing:
#                                 new_tm = TeamMember(case_id=case.id, user_id=tm_user.id)
#                                 session.add(new_tm)
#                                 session.commit()
#                                 st.success('Added')
#                                 st.rerun()
#                             else:
#                                 st.info('Already a member')
#                 team_members = [tm.member.username for tm in case.team_members]
#                 st.write(f'Team Members: {", ".join(team_members)}')
    
#     # User view: My Cases
#     st.subheader('My Accessible Cases')
#     if not accessible_cases:
#         st.info('No cases accessible.')
#     else:
#         for case in accessible_cases:
#             with st.expander(f'Case: {case.title} (ID: {case.id})'):
#                 st.write(f'Description: {case.description}')
#                 st.write(f'Enquiring Officer: {case.enquiring_officer.username if case.enquiring_officer else "N/A"}')
#                 if st.button('View Details', key=f'view_{case.id}'):
#                     log_access(session, user_id, case.id, operation='view_case')
#                     st.write('Case details viewed (logged).')
#                 evidences = case.evidences
#                 if evidences:
#                     st.write('Evidences:')
#                     for evidence in evidences:
#                         st.write(f'- {evidence.file_name} (Uploaded: {evidence.uploaded_at})')
#                         metadata = json.loads(evidence.evidence_metadata) if evidence.evidence_metadata else {}
#                         st.write(f'  Metadata: {metadata}')
                        
#                         # Button to start/stop analysis
#                         col1, col2 = st.columns([1, 4])
#                         with col1:
#                             if st.button(f'Analyze', key=f'analyze_{evidence.id}'):
#                                 if st.session_state.active_evidence_id == evidence.id:
#                                     # Close the chat
#                                     st.session_state.active_evidence_id = None
#                                 else:
#                                     # Open the chat for this evidence and load history
#                                     st.session_state.active_evidence_id = evidence.id
                                    
#                                     # Load chat history from access logs if not already loaded
#                                     if evidence.id not in st.session_state.chat_loaded:
#                                         chat_history = load_chat_history(session, evidence.id, user_id)
#                                         st.session_state.chat_messages[evidence.id] = chat_history
#                                         st.session_state.chat_loaded[evidence.id] = True
                                    
#                                     log_access(session, user_id, case.id, evidence.id, 'open_analysis')
#                                 st.rerun()
                        
#                         # Display chat interface if this evidence is active
#                         if st.session_state.active_evidence_id == evidence.id:
#                             if evidence.id not in st.session_state.chat_messages:
#                                 chat_history = load_chat_history(session, evidence.id, user_id)
#                                 st.session_state.chat_messages[evidence.id] = chat_history
#                                 st.session_state.chat_loaded[evidence.id] = True
                            
#                             st.markdown(f"**Chat for {evidence.file_name}**")
#                             st.caption(f"💬 {len([m for m in st.session_state.chat_messages[evidence.id] if m['role'] == 'user'])} previous queries in history")
                            
#                             # Display chat history
#                             for message in st.session_state.chat_messages[evidence.id]:
#                                 if message["role"] == "user":
#                                     with st.chat_message("user"):
#                                         st.markdown(message["content"])
#                                         if "user" in message and message["user"] != user.username:
#                                             st.caption(f"*Asked by {message['user']} at {message.get('timestamp', 'N/A')}*")
#                                 else:
#                                     with st.chat_message("assistant"):
#                                         st.markdown(message["content"])
#                                         if "tool_called" in message and message["tool_called"]:
#                                             st.caption(f"🔧 Tool used: {message['tool_called']}")
                            
#                             # Chat input
#                             query = st.chat_input(f"Ask about {evidence.file_name}", key=f"chat_input_{evidence.id}")
#                             if query:
#                                 # Add user message
#                                 with st.chat_message("user"):
#                                     st.markdown(query)
#                                 st.session_state.chat_messages[evidence.id].append({
#                                     "role": "user", 
#                                     "content": query,
#                                     "user": user.username,
#                                     "timestamp": datetime.datetime.utcnow()
#                                 })
                                
#                                 # Process the query
#                                 file_path = evidence.file_path
#                                 with open(file_path, 'rb') as f:
#                                     file_content = f.read()
#                                 ext = os.path.splitext(evidence.file_name)[1]
                                
#                                 with st.spinner("Analyzing..."):
#                                     result, tool_info = process_forensics_query(query, file_content, ext)
                                
#                                 # Add assistant response
#                                 with st.chat_message("assistant"):
#                                     st.markdown(result)
#                                     if tool_info['tool_called']:
#                                         st.caption(f"🔧 Tool used: {tool_info['tool_called']}")
                                
#                                 st.session_state.chat_messages[evidence.id].append({
#                                     "role": "assistant", 
#                                     "content": result,
#                                     "tool_called": tool_info['tool_called'],
#                                     "timestamp": datetime.datetime.utcnow()
#                                 })
                                
#                                 # Log the detailed access with chain of custody info
#                                 log_access(
#                                     session, 
#                                     user_id, 
#                                     case.id, 
#                                     evidence.id, 
#                                     'analyze_evidence',
#                                     query=query,
#                                     tool_called=tool_info['tool_called'],
#                                     tool_arguments=tool_info['tool_arguments'],
#                                     tool_result=tool_info['tool_result'],
#                                     llm_response=result
#                                 )
                                
#                                 st.rerun()
                        
#                         # Display Chain of Custody logs for this evidence
#                         with st.expander(f"📋 Chain of Custody - {evidence.file_name}"):
#                             evidence_logs = session.query(AccessLog).filter_by(evidence_id=evidence.id).order_by(AccessLog.timestamp.desc()).all()
                            
#                             if not evidence_logs:
#                                 st.info("No access logs for this evidence yet.")
#                             else:
#                                 for log in evidence_logs:
#                                     st.markdown("---")
#                                     col1, col2 = st.columns([2, 3])
                                    
#                                     with col1:
#                                         st.write(f"**👤 User:** {log.user.username}")
#                                         st.write(f"**📅 Time:** {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
#                                         st.write(f"**🔧 Operation:** {log.operation}")
                                    
#                                     with col2:
#                                         if log.query:
#                                             st.write(f"**❓ Query:** {log.query}")
#                                         if log.tool_called:
#                                             st.write(f"**🛠️ Tool Called:** {log.tool_called}")
#                                         if log.tool_arguments:
#                                             try:
#                                                 args = json.loads(log.tool_arguments)
#                                                 if args:
#                                                     st.write(f"**⚙️ Arguments:** {args}")
#                                             except:
#                                                 pass
#                                         if log.tool_result:
#                                             with st.expander("View Tool Result"):
#                                                 st.text(log.tool_result[:500] + "..." if len(log.tool_result) > 500 else log.tool_result)
#                                         if log.llm_response:
#                                             with st.expander("View LLM Response"):
#                                                 st.write(log.llm_response)
#                 else:
#                     st.write('No evidences.')
#                 team_members = [tm.member.username for tm in case.team_members]
#                 st.write(f'Team Members: {", ".join(team_members)}')
                
#                 # Case-level access logs
#                 if is_admin or (case.enquiring_officer_id == user_id):
#                     with st.expander('📊 Case Access Logs'):
#                         logs = session.query(AccessLog).filter_by(case_id=case.id).order_by(AccessLog.timestamp.desc()).all()
                        
#                         if not logs:
#                             st.info("No access logs for this case yet.")
#                         else:
#                             for log in logs:
#                                 ev_name = log.evidence.file_name if log.evidence else 'Case Level'
#                                 st.write(f"**{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** - "
#                                         f"User: *{log.user.username}* | "
#                                         f"Operation: *{log.operation}* | "
#                                         f"Target: *{ev_name}*")
                                
#                                 if log.query:
#                                     st.write(f"  └─ Query: {log.query}")
#                                 if log.tool_called:
#                                     st.write(f"  └─ Tool: {log.tool_called}")

#     if is_admin:
#         st.subheader('🔍 All Access Logs (Admin View)')
        
#         # Filter options
#         col1, col2, col3 = st.columns(3)
#         with col1:
#             filter_user = st.selectbox("Filter by User", ["All"] + [u.username for u in session.query(User).all()])
#         with col2:
#             filter_case = st.selectbox("Filter by Case", ["All"] + [f"{c.id}: {c.title}" for c in session.query(Case).all()])
#         with col3:
#             filter_operation = st.selectbox("Filter by Operation", ["All", "view_case", "analyze_evidence", "open_analysis"])
        
#         # Build query
#         query = session.query(AccessLog).order_by(AccessLog.timestamp.desc())
        
#         if filter_user != "All":
#             user_obj = session.query(User).filter_by(username=filter_user).first()
#             if user_obj:
#                 query = query.filter_by(user_id=user_obj.id)
        
#         if filter_case != "All":
#             case_id = int(filter_case.split(":")[0])
#             query = query.filter_by(case_id=case_id)
        
#         if filter_operation != "All":
#             query = query.filter_by(operation=filter_operation)
        
#         all_logs = query.limit(100).all()
        
#         st.write(f"Showing {len(all_logs)} logs (max 100)")
        
#         for log in all_logs:
#             ev_name = log.evidence.file_name if log.evidence else 'Case Level'
            
#             with st.expander(f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {log.user.username} - {log.operation} on {ev_name}"):
#                 col1, col2 = st.columns(2)
                
#                 with col1:
#                     st.write(f"**User:** {log.user.username}")
#                     st.write(f"**Case ID:** {log.case_id}")
#                     st.write(f"**Evidence:** {ev_name}")
#                     st.write(f"**Operation:** {log.operation}")
#                     st.write(f"**Timestamp:** {log.timestamp}")
                
#                 with col2:
#                     if log.query:
#                         st.write(f"**Query:**")
#                         st.info(log.query)
                    
#                     if log.tool_called:
#                         st.write(f"**Tool Called:** `{log.tool_called}`")
                    
#                     if log.tool_arguments:
#                         st.write(f"**Tool Arguments:**")
#                         try:
#                             args = json.loads(log.tool_arguments)
#                             st.json(args)
#                         except:
#                             st.text(log.tool_arguments)
                
#                 if log.tool_result:
#                     st.write("**Tool Result:**")
#                     with st.expander("View Full Result"):
#                         st.text(log.tool_result)
                
#                 if log.llm_response:
#                     st.write("**LLM Response:**")
#                     st.markdown(log.llm_response)

# session.close()


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
import winreg
import codecs
import sqlite3
import glob
from datetime import timedelta
try:
    import win32crypt
except ImportError:
    win32crypt = None
import re
import base64
import io
import mimetypes
import zipfile
from collections import defaultdict, Counter
try:
    from scapy.all import rdpcap, TCP, Raw, IP, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
import mimetypes
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


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
    operation = Column(String(50), nullable=False)  # e.g., 'view_case', 'analyze_evidence'
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # NEW FIELDS for Chain of Custody
    query = Column(Text, nullable=True)  # User's natural language query
    tool_called = Column(String(100), nullable=True)  # Name of the tool that was called
    tool_arguments = Column(Text, nullable=True)  # JSON string of tool arguments
    tool_result = Column(Text, nullable=True)  # Result returned by the tool
    llm_response = Column(Text, nullable=True)  # Final LLM response to user
    
    # Relationships
    user = relationship('User', back_populates='access_logs')
    case = relationship('Case', back_populates='access_logs')
    evidence = relationship('Evidence', back_populates='access_logs')

# Force configuration of mappers after all classes defined
configure_mappers()

# Setup DB with check to avoid recreation
engine = create_engine('sqlite:///forensics.db')
inspector = inspect(engine)

# Create all tables if database is new
if not inspector.has_table('users'):
    Base.metadata.create_all(engine)
    print("✓ Database created with all tables")
else:
    # For existing database, try to add new columns if they don't exist
    try:
        # This will add any missing columns/tables
        Base.metadata.create_all(engine)
        
        # Verify and add missing columns to access_logs if needed
        with engine.connect() as conn:
            # Check if new columns exist in access_logs
            result = conn.execute("PRAGMA table_info(access_logs)").fetchall()
            existing_columns = [row[1] for row in result]
            
            new_columns = {
                'query': 'TEXT',
                'tool_called': 'VARCHAR(100)',
                'tool_arguments': 'TEXT',
                'tool_result': 'TEXT',
                'llm_response': 'TEXT'
            }
            
            for col_name, col_type in new_columns.items():
                if col_name not in existing_columns:
                    conn.execute(f"ALTER TABLE access_logs ADD COLUMN {col_name} {col_type}")
                    conn.commit()
                    print(f"✓ Added column '{col_name}' to access_logs table")
    except Exception as e:
        print(f"Note: Schema update attempt: {e}")

Session = sessionmaker(bind=engine)

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    return stored_hash == hashlib.sha256(password.encode()).hexdigest()

def log_access(session, user_id, case_id, evidence_id=None, operation='view', 
               query=None, tool_called=None, tool_arguments=None, tool_result=None, llm_response=None):
    """Enhanced logging function with chain of custody details"""
    log = AccessLog(
        user_id=user_id, 
        case_id=case_id, 
        evidence_id=evidence_id, 
        operation=operation,
        query=query,
        tool_called=tool_called,
        tool_arguments=tool_arguments,
        tool_result=tool_result,
        llm_response=llm_response
    )
    session.add(log)
    session.commit()
    return log

def init_data(session):
    """Initialize default users if they don't exist"""
    # Create admin user
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password_hash=hash_password('adminpass'), is_admin=True)
        session.add(admin)
        print("✓ Created admin user (username: admin, password: adminpass)")
    
    # Create officer1 user
    user1 = session.query(User).filter_by(username='officer1').first()
    if not user1:
        user1 = User(username='officer1', password_hash=hash_password('pass1'), is_admin=False)
        session.add(user1)
        print("✓ Created officer1 user (username: officer1, password: pass1)")
    
    # Create member1 user
    user2 = session.query(User).filter_by(username='member1').first()
    if not user2:
        user2 = User(username='member1', password_hash=hash_password('pass2'), is_admin=False)
        session.add(user2)
        print("✓ Created member1 user (username: member1, password: pass2)")
    
    session.commit()
    
    # Display summary
    total_users = session.query(User).count()
    print(f"✓ Database initialized with {total_users} users")

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
    }, func_name, args, result

# Main function to process query - now returns detailed info for logging
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
    
    tool_info = {
        'tool_called': None,
        'tool_arguments': None,
        'tool_result': None
    }
    
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
        return f"API Error: {str(e)}", tool_info
    
    response_message = response.choices[0].message
    tool_calls = response_message.tool_calls
    
    if tool_calls:
        messages.append(response_message)
        tool_results = []
        for tool_call in tool_calls:
            tool_response, func_name, args, result = execute_tool(tool_call, file_content, ext)
            messages.append(tool_response)
            tool_results.append(tool_response["content"])
            
            # Store tool info for logging (last tool if multiple)
            tool_info['tool_called'] = func_name
            tool_info['tool_arguments'] = json.dumps(args)
            tool_info['tool_result'] = result
        
        try:
            final_response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            print("Final Response:", final_response)
            content = final_response.choices[0].message.content
            return (content if content else tool_results[0]), tool_info
        except Exception as e:
            return f"Final API Error: {str(e)}", tool_info
    else:
        return (response_message.content or "Error: No tool called and no direct response provided."), tool_info

def load_chat_history(session, evidence_id, current_user_id):
    """Load chat history from access logs for a specific evidence file"""
    logs = session.query(AccessLog).filter(
        AccessLog.evidence_id == evidence_id,
        AccessLog.operation == 'analyze_evidence',
        AccessLog.query.isnot(None)
    ).order_by(AccessLog.timestamp).all()
    
    chat_history = []
    for log in logs:
        # Add user query
        chat_history.append({
            "role": "user",
            "content": log.query,
            "timestamp": log.timestamp,
            "user": log.user.username
        })
        
        # Add assistant response
        if log.llm_response:
            chat_history.append({
                "role": "assistant",
                "content": log.llm_response,
                "timestamp": log.timestamp,
                "tool_called": log.tool_called
            })
    
    return chat_history

def create_new_case_ui(session, all_users):
    """UI for admin to create a new case"""
    st.subheader("➕ Create New Case")
    
    with st.form("create_case_form"):
        case_title = st.text_input("Case Title*", placeholder="Enter case title")
        case_description = st.text_area("Case Description", placeholder="Enter case description (optional)")
        
        # Dropdown for selecting enquiring officer
        officer_usernames = [u.username for u in all_users]
        selected_officer = st.selectbox("Enquiring Officer*", officer_usernames, index=0)
        
        # File uploader for evidence
        evidence_files = st.file_uploader(
            "Upload Evidence Files", 
            accept_multiple_files=True,
            help="Upload one or more evidence files for this case"
        )
        
        submit_button = st.form_submit_button("Create Case", type="primary")
        
        if submit_button:
            if not case_title:
                st.error("❌ Case title is required!")
                return
            
            if not selected_officer:
                st.error("❌ Please select an enquiring officer!")
                return
            
            # Get the officer user object
            officer = session.query(User).filter_by(username=selected_officer).first()
            
            if not officer:
                st.error("❌ Selected officer not found!")
                return
            
            # Create the case
            new_case = Case(
                title=case_title,
                description=case_description if case_description else None,
                enquiring_officer=officer
            )
            session.add(new_case)
            session.commit()
            
            # Create evidence directory if it doesn't exist
            evidence_dir = 'evidences'
            os.makedirs(evidence_dir, exist_ok=True)
            
            # Upload evidence files
            if evidence_files:
                for uploaded_file in evidence_files:
                    # Save file with case prefix
                    file_path = os.path.join(evidence_dir, f"case_{new_case.id}_{uploaded_file.name}")
                    
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    
                    # Create metadata
                    metadata = {
                        'original_name': uploaded_file.name,
                        'size': uploaded_file.size,
                        'type': uploaded_file.type
                    }
                    
                    # Create evidence record
                    evidence = Evidence(
                        case_id=new_case.id,
                        file_name=uploaded_file.name,
                        file_path=file_path,
                        evidence_metadata=json.dumps(metadata)
                    )
                    session.add(evidence)
                
                session.commit()
                st.success(f"✅ Case '{case_title}' created successfully with {len(evidence_files)} evidence file(s)!")
            else:
                st.success(f"✅ Case '{case_title}' created successfully (no evidence files uploaded)!")
            
            st.info(f"Case ID: {new_case.id} | Officer: {officer.username}")
            st.rerun()

# Streamlit UI
st.title('Computer Forensics Prototype - Chain of Custody System')

session = Session()
init_data(session)

# Initialize session state for active evidence analysis
if 'active_evidence_id' not in st.session_state:
    st.session_state.active_evidence_id = None

if 'chat_messages' not in st.session_state:
    st.session_state.chat_messages = {}

if 'chat_loaded' not in st.session_state:
    st.session_state.chat_loaded = {}

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
        st.session_state.chat_messages = {}
        st.session_state.chat_loaded = {}
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
    
    # Sidebar case selection
    st.sidebar.header("Cases")
    case_options = ["Select a Case",] + [f"{case.id}: {case.title}" for case in accessible_cases]
    if is_admin:
        case_options = ["Create a new case",] + case_options
    selected_case_option = st.sidebar.selectbox("Choose a Case", case_options, key="case_select")
    selected_case = None
    if selected_case_option ==  "Create a new case":
        create_new_case_ui(session, session.query(User).all())
        
    if selected_case_option not in ["Create a new case", "Select a Case"]:
        case_id = int(selected_case_option.split(":")[0])
        selected_case = session.query(Case).filter_by(id=case_id).first()
    
    # Main content area for case details
    if selected_case:
        st.header(f"Case: {selected_case.title} (ID: {selected_case.id})")
        st.write(f"**Description:** {selected_case.description}")
        st.write(f"**Enquiring Officer:** {selected_case.enquiring_officer.username if selected_case.enquiring_officer else 'N/A'}")
        
        if st.button('View Details', key=f'view_{selected_case.id}'):
            log_access(session, user_id, selected_case.id, operation='view_case')
            st.success('Case details viewed (logged).')
        
        evidences = selected_case.evidences
        if evidences:
            st.subheader("Evidences")
            for evidence in evidences:
                st.write(f"- **{evidence.file_name}** (Uploaded: {evidence.uploaded_at})")
                metadata = json.loads(evidence.evidence_metadata) if evidence.evidence_metadata else {}
                st.write(f"  **Metadata:** {metadata}")
                
                # Button to start/stop analysis
                col1, col2 = st.columns([1, 4])
                with col1:
                    if st.button(f'Analyze', key=f'analyze_{evidence.id}'):
                        if st.session_state.active_evidence_id == evidence.id:
                            # Close the chat
                            st.session_state.active_evidence_id = None
                        else:
                            # Open the chat for this evidence and load history
                            st.session_state.active_evidence_id = evidence.id
                            
                            # Load chat history from access logs if not already loaded
                            if evidence.id not in st.session_state.chat_loaded:
                                chat_history = load_chat_history(session, evidence.id, user_id)
                                st.session_state.chat_messages[evidence.id] = chat_history
                                st.session_state.chat_loaded[evidence.id] = True
                            
                            log_access(session, user_id, selected_case.id, evidence.id, 'open_analysis')
                        st.rerun()
                
                # Display chat interface if this evidence is active
                if st.session_state.active_evidence_id == evidence.id:
                    if evidence.id not in st.session_state.chat_messages:
                        chat_history = load_chat_history(session, evidence.id, user_id)
                        st.session_state.chat_messages[evidence.id] = chat_history
                        st.session_state.chat_loaded[evidence.id] = True
                    
                    st.markdown(f"**Chat for {evidence.file_name}**")
                    st.caption(f"💬 {len([m for m in st.session_state.chat_messages[evidence.id] if m['role'] == 'user'])} previous queries in history")
                    
                    # Display chat history
                    for message in st.session_state.chat_messages[evidence.id]:
                        if message["role"] == "user":
                            with st.chat_message("user"):
                                st.markdown(message["content"])
                                if "user" in message and message["user"] != user.username:
                                    st.caption(f"*Asked by {message['user']} at {message.get('timestamp', 'N/A')}*")
                        else:
                            with st.chat_message("assistant"):
                                st.markdown(message["content"])
                                if "tool_called" in message and message["tool_called"]:
                                    st.caption(f"🔧 Tool used: {message['tool_called']}")
                    
                    # Chat input
                    query = st.chat_input(f"Ask about {evidence.file_name}", key=f"chat_input_{evidence.id}")
                    if query:
                        # Add user message
                        with st.chat_message("user"):
                            st.markdown(query)
                        st.session_state.chat_messages[evidence.id].append({
                            "role": "user", 
                            "content": query,
                            "user": user.username,
                            "timestamp": datetime.datetime.utcnow()
                        })
                        
                        # Process the query
                        file_path = evidence.file_path
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        ext = os.path.splitext(evidence.file_name)[1]
                        
                        with st.spinner("Analyzing..."):
                            result, tool_info = process_forensics_query(query, file_content, ext)
                        
                        # Add assistant response
                        with st.chat_message("assistant"):
                            st.markdown(result)
                            if tool_info['tool_called']:
                                st.caption(f"🔧 Tool used: {tool_info['tool_called']}")
                        
                        st.session_state.chat_messages[evidence.id].append({
                            "role": "assistant", 
                            "content": result,
                            "tool_called": tool_info['tool_called'],
                            "timestamp": datetime.datetime.utcnow()
                        })
                        
                        # Log the detailed access with chain of custody info
                        log_access(
                            session, 
                            user_id, 
                            selected_case.id, 
                            evidence.id, 
                            'analyze_evidence',
                            query=query,
                            tool_called=tool_info['tool_called'],
                            tool_arguments=tool_info['tool_arguments'],
                            tool_result=tool_info['tool_result'],
                            llm_response=result
                        )
                        
                        st.rerun()
                
                # Display Chain of Custody logs for this evidence
                with st.expander(f"📋 Chain of Custody - {evidence.file_name}"):
                    evidence_logs = session.query(AccessLog).filter_by(evidence_id=evidence.id).order_by(AccessLog.timestamp.desc()).all()
                    
                    if not evidence_logs:
                        st.info("No access logs for this evidence yet.")
                    else:
                        for log in evidence_logs:
                            st.markdown("---")
                            col1, col2 = st.columns([2, 3])
                            
                            with col1:
                                st.write(f"**👤 User:** {log.user.username}")
                                st.write(f"**📅 Time:** {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                                st.write(f"**🔧 Operation:** {log.operation}")
                            
                            with col2:
                                if log.query:
                                    st.write(f"**❓ Query:** {log.query}")
                                if log.tool_called:
                                    st.write(f"**🛠️ Tool Called:** {log.tool_called}")
                                if log.tool_arguments:
                                    try:
                                        args = json.loads(log.tool_arguments)
                                        if args:
                                            st.write(f"**⚙️ Arguments:** {args}")
                                    except:
                                        pass
                                if log.tool_result:
                                    with st.expander("View Tool Result"):
                                        st.text(log.tool_result[:500] + "..." if len(log.tool_result) > 500 else log.tool_result)
                                if log.llm_response:
                                    with st.expander("View LLM Response"):
                                        st.write(log.llm_response)
        
        st.subheader("Team Members")
        team_members = [tm.member.username for tm in selected_case.team_members]
        st.write(f"{', '.join(team_members) if team_members else 'None'}")
        
        # Case-level access logs
        if is_admin or (selected_case.enquiring_officer_id == user_id):
            with st.expander('📊 Case Access Logs'):
                logs = session.query(AccessLog).filter_by(case_id=selected_case.id).order_by(AccessLog.timestamp.desc()).all()
                
                if not logs:
                    st.info("No access logs for this case yet.")
                else:
                    for log in logs:
                        ev_name = log.evidence.file_name if log.evidence else 'Case Level'
                        st.write(f"**{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** - "
                                f"User: *{log.user.username}* | "
                                f"Operation: *{log.operation}* | "
                                f"Target: *{ev_name}*")
                        
                        if log.query:
                            st.write(f"  └─ Query: {log.query}")
                        if log.tool_called:
                            st.write(f"  └─ Tool: {log.tool_called}")
    else:
        st.write("Please select a case from the sidebar to view details.")

    if is_admin:
        st.subheader('🔍 All Access Logs (Admin View)')
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            filter_user = st.selectbox("Filter by User", ["All"] + [u.username for u in session.query(User).all()])
        with col2:
            filter_case = st.selectbox("Filter by Case", ["All"] + [f"{c.id}: {c.title}" for c in session.query(Case).all()])
        with col3:
            filter_operation = st.selectbox("Filter by Operation", ["All", "view_case", "analyze_evidence", "open_analysis"])
        
        # Build query
        query = session.query(AccessLog).order_by(AccessLog.timestamp.desc())
        
        if filter_user != "All":
            user_obj = session.query(User).filter_by(username=filter_user).first()
            if user_obj:
                query = query.filter_by(user_id=user_obj.id)
        
        if filter_case != "All":
            case_id = int(filter_case.split(":")[0])
            query = query.filter_by(case_id=case_id)
        
        if filter_operation != "All":
            query = query.filter_by(operation=filter_operation)
        
        all_logs = query.limit(100).all()
        
        st.write(f"Showing {len(all_logs)} logs (max 100)")
        
        for log in all_logs:
            ev_name = log.evidence.file_name if log.evidence else 'Case Level'
            
            with st.expander(f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {log.user.username} - {log.operation} on {ev_name}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**User:** {log.user.username}")
                    st.write(f"**Case ID:** {log.case_id}")
                    st.write(f"**Evidence:** {ev_name}")
                    st.write(f"**Operation:** {log.operation}")
                    st.write(f"**Timestamp:** {log.timestamp}")
                
                with col2:
                    if log.query:
                        st.write(f"**Query:**")
                        st.info(log.query)
                    
                    if log.tool_called:
                        st.write(f"**Tool Called:** `{log.tool_called}`")
                    
                    if log.tool_arguments:
                        st.write(f"**Tool Arguments:**")
                        try:
                            args = json.loads(log.tool_arguments)
                            st.json(args)
                        except:
                            st.text(log.tool_arguments)
                
                if log.tool_result:
                    st.write("**Tool Result:**")
                    with st.expander("View Full Result"):
                        st.text(log.tool_result)
                
                if log.llm_response:
                    st.write("**LLM Response:**")
                    st.markdown(log.llm_response)

session.close()


