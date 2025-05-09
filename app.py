import streamlit as st
import datetime
import pandas as pd
from PIL import Image
import io
import base64
import hashlib
import uuid
import logging
import json
import os
import re
from typing import Dict, List, Optional, Tuple, Any, Union
import time
import random

CONFIG = {
    "version": "1.0.0",
    "allowed_file_types": ["jpg", "jpeg", "png", "pdf", "dcm"],
    "max_upload_size_mb": 10
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("healthcare-assistant")

# Load configuration
def load_config():
    env = os.environ.get("ENVIRONMENT", "development")
    try:
        with open(f"config.{env}.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration
        return {
            "app_name": "Enterprise Healthcare Assistant",
            "session_expiry_hours": 24,
            "password_min_length": 8,
            "enable_analytics": True,
            "enable_notifications": True,
            "max_upload_size_mb": 10,
            "allowed_file_types": ["jpg", "jpeg", "png", "pdf", "dicom"]
        }

CONFIG = load_config()

# Set page configuration
st.set_page_config(
    page_title=CONFIG["app_name"],
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Security functions
def hash_password(password: str) -> str:
    """Hash a password for storing."""
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    hash_part, salt = stored_password.split(':')
    return hash_part == hashlib.sha256(salt.encode() + provided_password.encode()).hexdigest()

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength"""
    if len(password) < CONFIG["password_min_length"]:
        return False, f"Password must be at least {CONFIG['password_min_length']} characters long"
    
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    
    return True, ""

def check_session_expiry():
    """Check if the user session has expired"""
    if "last_activity" in st.session_state:
        expiry_time = datetime.timedelta(hours=CONFIG["session_expiry_hours"])
        if datetime.datetime.now() - st.session_state.last_activity > expiry_time:
            logger.info(f"Session expired for user: {st.session_state.get('user_email', 'unknown')}")
            logout()
            st.warning("Your session has expired. Please log in again.")
            return True
    
    # Update last activity
    st.session_state.last_activity = datetime.datetime.now()
    return False

# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "current_page" not in st.session_state:
    st.session_state.current_page = "login"
if "last_activity" not in st.session_state:
    st.session_state.last_activity = datetime.datetime.now()
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "users" not in st.session_state:
    # Simulated user database with hashed passwords
    st.session_state.users = {
        "doctor@example.com": {"password": hash_password("doctor123"), "role": "Doctor"},
        "patient@example.com": {"password": hash_password("patient123"), "role": "Patient"}
    }
if "patient_data" not in st.session_state:
    # Simulated patient database
    st.session_state.patient_data = {
        "aditi@example.com": {
            "id": "P001",
            "name": "Aditi Sharma",
            "records": [
                {"date": "Apr 19", "symptoms": "Fever, Cough", "diagnosis": "Possible Flu"}
            ],
            "reports": [
                {"date": "Apr 19", "type": "X-ray", "notes": "Chest X-ray shows clear lungs"}
            ]
        },
        "rakesh@example.com": {
            "id": "P002",
            "name": "Rakesh Verma",
            "records": [
                {"date": "Apr 18", "symptoms": "Chest Pain", "diagnosis": "Possible Pneumonia"}
            ],
            "reports": [
                {"date": "Apr 18", "type": "Blood Test", "notes": "Elevated white blood cell count"}
            ]
        },
        "neha@example.com": {
            "id": "P003",
            "name": "Neha Singh",
            "records": [
                {"date": "Apr 17", "symptoms": "Fatigue, Headache", "diagnosis": "Possible Anemia"}
            ],
            "reports": [
                {"date": "Apr 17", "type": "Blood Test", "notes": "Low hemoglobin levels"}
            ]
        },
        "patient@example.com": {
            "id": "P004",
            "name": "Test Patient",
            "records": [
                {"date": "Apr 15", "symptoms": "Headache, Nausea", "diagnosis": "Migraine"},
                {"date": "Apr 14", "symptoms": "Cough, Fatigue", "diagnosis": "Mild Flu"}
            ],
            "reports": [
                {"date": "Apr 15", "type": "MRI", "notes": "Normal brain scan"},
                {"date": "Apr 14", "type": "X-ray", "notes": "Clear chest X-ray"}
            ]
        }
    }
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

# Custom CSS with improved enterprise styling
st.markdown("""
<style>
    /* Enterprise color scheme */
    :root {
        --primary-color: #0066cc;
        --secondary-color: #0052a3;
        --accent-color: #00a3e0;
        --success-color: #28a745;
        --warning-color: #ffc107;
        --danger-color: #dc3545;
        --light-color: #f8f9fa;
        --dark-color: #343a40;
        --text-color: #212529;
        --text-muted: #6c757d;
        --border-color: #dee2e6;
    }
    
    /* Typography */
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: var(--text-color);
    }
    
    .main-header {
        font-size: 2.5rem;
        color: var(--primary-color);
        text-align: center;
        margin-bottom: 1.5rem;
        font-weight: 600;
    }
    
    .sub-header {
        font-size: 1.8rem;
        color: var(--secondary-color);
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        font-weight: 500;
    }
    
    /* Cards */
    .card {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: white;
        border: 1px solid var(--border-color);
        margin: 0.75rem 0;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    }
    
    .card-title {
        font-size: 1.3rem;
        font-weight: 600;
        color: var(--primary-color);
        margin-bottom: 0.75rem;
    }
    
    /* Buttons */
    .stButton>button {
        background-color: var(--primary-color);
        color: white;
        border-radius: 4px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        border: none;
        transition: background-color 0.3s;
    }
    
    .stButton>button:hover {
        background-color: var(--secondary-color);
    }
    
    /* Navigation */
    .sidebar .sidebar-content {
        background-color: var(--light-color);
    }
    
    /* Messages */
    .success-msg {
        padding: 1rem;
        background-color: #d4edda;
        color: #155724;
        border-radius: 0.25rem;
        margin: 1rem 0;
        border-left: 4px solid var(--success-color);
    }
    
    .error-msg {
        padding: 1rem;
        background-color: #f8d7da;
        color: #721c24;
        border-radius: 0.25rem;
        margin: 1rem 0;
        border-left: 4px solid var(--danger-color);
    }
    
    .warning-msg {
        padding: 1rem;
        background-color: #fff3cd;
        color: #856404;
        border-radius: 0.25rem;
        margin: 1rem 0;
        border-left: 4px solid var(--warning-color);
    }
    
    .info-msg {
        padding: 1rem;
        background-color: #d1ecf1;
        color: #0c5460;
        border-radius: 0.25rem;
        margin: 1rem 0;
        border-left: 4px solid var(--accent-color);
    }
    
    /* Footer */
    .footer {
        text-align: center;
        margin-top: 2rem;
        padding: 1.5rem;
        background-color: var(--light-color);
        border-top: 1px solid var(--border-color);
        color: var(--text-muted);
        font-size: 0.9rem;
    }
    
    /* Tables */
    .dataframe {
        width: 100%;
        border-collapse: collapse;
    }
    
    .dataframe th {
        background-color: var(--primary-color);
        color: white;
        padding: 0.75rem;
        text-align: left;
    }
    
    .dataframe td {
        padding: 0.75rem;
        border-bottom: 1px solid var(--border-color);
    }
    
    .dataframe tr:nth-child(even) {
        background-color: rgba(0,0,0,0.02);
    }
    
    /* Form elements */
    input, select, textarea {
        border-radius: 4px !important;
        border: 1px solid var(--border-color) !important;
    }
    
    /* Accessibility */
    a:focus, button:focus, input:focus, select:focus, textarea:focus {
        outline: 2px solid var(--accent-color) !important;
        outline-offset: 2px !important;
    }
    
    /* Loading spinner */
    .stSpinner > div {
        border-color: var(--primary-color) !important;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions
def login(email: str, password: str) -> bool:
    """Authenticate user with email and password"""
    try:
        if not email or not password:
            return False
            
        if email not in st.session_state.users:
            logger.warning(f"Login attempt with unknown email: {email}")
            return False
            
        stored_password = st.session_state.users[email]["password"]
        if not verify_password(stored_password, password):
            logger.warning(f"Failed login attempt for user: {email}")
            return False
            
        st.session_state.authenticated = True
        st.session_state.user_role = st.session_state.users[email]["role"]
        st.session_state.user_email = email
        st.session_state.last_activity = datetime.datetime.now()
        
        if st.session_state.user_role == "Doctor":
            st.session_state.current_page = "doctor_dashboard"
        else:
            st.session_state.current_page = "patient_dashboard"
            
        # Log successful login
        log_activity("login", f"User logged in: {email}")
        logger.info(f"Successful login: {email}")
        return True
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return False

def signup(email: str, password: str, role: str) -> Tuple[bool, str]:
    """Register a new user"""
    try:
        # Validate inputs
        if not email or not password or not role:
            return False, "All fields are required"
            
        if not validate_email(email):
            return False, "Invalid email format"
            
        valid_password, password_msg = validate_password(password)
        if not valid_password:
            return False, password_msg
            
        if email in st.session_state.users:
            logger.warning(f"Signup attempt with existing email: {email}")
            return False, "Email already exists"
        
        # Create user
        st.session_state.users[email] = {"password": hash_password(password), "role": role}
        
        # If it's a patient, create empty patient data
        if role == "Patient" and email not in st.session_state.patient_data:
            st.session_state.patient_data[email] = {
                "id": f"P{len(st.session_state.patient_data) + 1:03d}",
                "name": email.split('@')[0].title(),
                "records": [],
                "reports": []
            }
        
        # Log activity
        log_activity("signup", f"New user registered: {email} as {role}")
        logger.info(f"New user registered: {email} as {role}")
        return True, "Account created successfully! Please login."
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return False, f"An error occurred: {str(e)}"

def logout():
    """Log out the current user"""
    if "user_email" in st.session_state:
        log_activity("logout", f"User logged out: {st.session_state.user_email}")
        logger.info(f"User logged out: {st.session_state.user_email}")
    
    # Clear session state
    for key in list(st.session_state.keys()):
        if key not in ["users", "patient_data", "audit_log"]:
            del st.session_state[key]
    
    # Reinitialize essential session state
    st.session_state.authenticated = False
    st.session_state.user_role = None
    st.session_state.current_page = "login"
    st.session_state.session_id = str(uuid.uuid4())
    st.session_state.last_activity = datetime.datetime.now()

def check_auth(required_role: Optional[str] = None) -> bool:
    """Check if user is authenticated and has required role"""
    # Check session expiry
    if check_session_expiry():
        return False
    
    if not st.session_state.authenticated:
        st.session_state.current_page = "login"
        return False
    
    if required_role and st.session_state.user_role != required_role:
        log_activity("unauthorized_access", 
                    f"User {st.session_state.user_email} attempted to access {required_role} page")
        logger.warning(f"Unauthorized access attempt: {st.session_state.user_email} tried to access {required_role} page")
        
        st.markdown(f"""
        <div class="error-msg">
            <strong>Access Denied.</strong> This section is for authorized {required_role.lower()}s only.
        </div>
        """, unsafe_allow_html=True)
        return False
    
    return True

def log_activity(action: str, description: str):
    """Log user activity for audit purposes"""
    st.session_state.audit_log.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "user": st.session_state.get("user_email", "anonymous"),
        "session_id": st.session_state.get("session_id", "unknown"),
        "action": action,
        "description": description,
        "ip_address": "127.0.0.1"  # In a real app, get the actual IP
    })

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent XSS attacks"""
    if not text:
        return ""
    # Remove HTML tags
    text = re.sub(r'<[^>]*>', '', text)
    # Escape special characters
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#39;')
    return text

# Navigation
def render_navigation():
    """Render the navigation sidebar"""
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/hospital-2.png", width=100)
        st.title(CONFIG["app_name"])
        
        if st.session_state.authenticated:
            st.markdown(f"**User:** {st.session_state.user_email}")
            st.markdown(f"**Role:** {st.session_state.user_role}")
            st.markdown("---")
            
            if st.session_state.user_role == "Doctor":
                if st.button("📊 Dashboard", key="nav_doctor_dashboard"):
                    st.session_state.current_page = "doctor_dashboard"
                    log_activity("navigation", "Navigated to doctor dashboard")
                
                if st.button("📋 Patient Reports", key="nav_view_reports"):
                    st.session_state.current_page = "view_reports"
                    log_activity("navigation", "Navigated to patient reports")
                
                if st.button("📝 Diagnosis Records", key="nav_diagnosis_records"):
                    st.session_state.current_page = "diagnosis_records"
                    log_activity("navigation", "Navigated to diagnosis records")
                
                if st.button("💬 Submit Feedback", key="nav_submit_feedback"):
                    st.session_state.current_page = "submit_feedback"
                    log_activity("navigation", "Navigated to submit feedback")
            else:  # Patient
                if st.button("📊 Dashboard", key="nav_patient_dashboard"):
                    st.session_state.current_page = "patient_dashboard"
                    log_activity("navigation", "Navigated to patient dashboard")
                
                if st.button("🔍 Check Symptoms", key="nav_symptom_checker"):
                    st.session_state.current_page = "symptom_checker"
                    log_activity("navigation", "Navigated to symptom checker")
                
                if st.button("📤 Upload Medical Report", key="nav_upload_report"):
                    st.session_state.current_page = "upload_report"
                    log_activity("navigation", "Navigated to upload report")
                
                if st.button("📜 View My History", key="nav_view_history"):
                    st.session_state.current_page = "view_history"
                    log_activity("navigation", "Navigated to view history")
        
        st.markdown("---")
        if st.button("ℹ️ About the System", key="nav_about"):
            st.session_state.current_page = "about"
            log_activity("navigation", "Navigated to about page")
        
        if st.session_state.authenticated:
            st.markdown("---")
            if st.button("🔒 Logout", key="nav_logout"):
                logout()
                st.experimental_rerun()

# Pages
def login_page():
    """Render the login page"""
    st.markdown('<h1 class="main-header">Healthcare Assistant</h1>', unsafe_allow_html=True)
    
    # Display a professional healthcare image
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image("https://img.icons8.com/color/240/000000/healthcare-and-medical.png", use_column_width=True)
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        with st.form("login_form"):
            email = st.text_input("Email", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")
            
            submitted = st.form_submit_button("Login")
            if submitted:
                with st.spinner("Authenticating..."):
                    time.sleep(0.5)  # Simulate network delay
                    if login(email, password):
                        st.success("Login successful!")
                        st.experimental_rerun()
                    else:
                        st.error("Invalid email or password")
    
    with tab2:
        with st.form("signup_form"):
            email = st.text_input("Email", key="signup_email")
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
            role = st.selectbox("User Role", ["Doctor", "Patient"])
            
            # Password strength indicator
            if password:
                if len(password) < 8:
                    st.warning("Password is too short")
                elif len(password) < 12:
                    st.warning("Password could be stronger")
                else:
                    st.success("Password strength: Good")
            
            # Terms and conditions
            terms_accepted = st.checkbox("I accept the Terms and Conditions")
            
            submitted = st.form_submit_button("Sign Up")
            if submitted:
                if not terms_accepted:
                    st.error("You must accept the Terms and Conditions")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    with st.spinner("Creating account..."):
                        time.sleep(0.5)  # Simulate network delay
                        success, message = signup(email, password, role)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)

def doctor_dashboard():
    """Render the doctor dashboard"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">Doctor Dashboard</h1>', unsafe_allow_html=True)
    
    # Welcome message with time-based greeting
    hour = datetime.datetime.now().hour
    greeting = "Good morning" if 5 <= hour < 12 else "Good afternoon" if 12 <= hour < 18 else "Good evening"
    st.markdown(f"### {greeting}, Dr. {st.session_state.user_email.split('@')[0].title()}")
    
    # Quick stats
    st.markdown("### Quick Statistics")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Patients", value=len(st.session_state.patient_data))
    with col2:
        st.metric(label="Reports Pending", value="3")
    with col3:
        st.metric(label="Appointments Today", value="5")
    with col4:
        st.metric(label="New Messages", value="2")
    
    # Cards
    st.markdown("### Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="card">
            <div class="card-title">View Uploaded Reports</div>
            <p>Access patient reports and medical images for diagnosis</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("View Reports", key="view_reports_btn"):
            st.session_state.current_page = "view_reports"
            log_activity("navigation", "Navigated to view reports from dashboard")
    
    with col2:
        st.markdown("""
        <div class="card">
            <div class="card-title">Patient Diagnosis Records</div>
            <p>Review patient diagnosis history and treatment plans</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("View Records", key="view_records_btn"):
            st.session_state.current_page = "diagnosis_records"
            log_activity("navigation", "Navigated to diagnosis records from dashboard")
    
    with col3:
        st.markdown("""
        <div class="card">
            <div class="card-title">Submit Feedback</div>
            <p>Provide feedback on diagnosis and treatment effectiveness</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Submit Feedback", key="submit_feedback_btn"):
            st.session_state.current_page = "submit_feedback"
            log_activity("navigation", "Navigated to submit feedback from dashboard")
    
    # Patient search
    st.markdown('<h2 class="sub-header">Patient Search</h2>', unsafe_allow_html=True)
    
    with st.form("patient_search_form"):
        search_query = st.text_input("Enter Patient Email or ID", key="search_query")
        submitted = st.form_submit_button("Search")
        
        if submitted:
            log_activity("search", f"Searched for patient: {search_query}")
            with st.spinner("Searching..."):
                time.sleep(0.5)  # Simulate search delay
                found = False
                for email, data in st.session_state.patient_data.items():
                    if search_query.lower() == email.lower() or search_query.lower() == data["id"].lower():
                        found = True
                        st.success(f"Patient found: {data['name']} (ID: {data['id']})")
                        
                        # Display patient records in tabs
                        tab1, tab2 = st.tabs(["Medical Records", "Reports"])
                        
                        with tab1:
                            if data["records"]:
                                records_df = pd.DataFrame(data["records"])
                                st.dataframe(records_df, use_container_width=True)
                            else:
                                st.info("No medical records found for this patient")
                        
                        with tab2:
                            if data["reports"]:
                                reports_df = pd.DataFrame(data["reports"])
                                st.dataframe(reports_df, use_container_width=True)
                            else:
                                st.info("No reports found for this patient")
                        
                        break
                
                if not found:
                    st.error("Patient Not Found or Access Denied")
    
    # Recent patient records
    st.markdown('<h2 class="sub-header">Recent Patient Records</h2>', unsafe_allow_html=True)
    
    records_data = []
    for email, data in st.session_state.patient_data.items():
        for record in data["records"]:
            records_data.append({
                "Patient Name": data["name"],
                "Patient ID": data["id"],
                "Date": record["date"],
                "Symptoms": record["symptoms"],
                "Diagnosis": record["diagnosis"]
            })
    
    if records_data:
        records_df = pd.DataFrame(records_data)
        st.dataframe(records_df, use_container_width=True)
    else:
        st.info("No patient records available")
    
    # Upcoming appointments (simulated)
    st.markdown('<h2 class="sub-header">Upcoming Appointments</h2>', unsafe_allow_html=True)
    
    appointments = [
        {"Patient": "Aditi Sharma", "Date": "Tomorrow, 10:00 AM", "Type": "Follow-up"},
        {"Patient": "Rakesh Verma", "Date": "Tomorrow, 11:30 AM", "Type": "New Consultation"},
        {"Patient": "Neha Singh", "Date": "Tomorrow, 2:00 PM", "Type": "Test Results"},
    ]
    
    appointments_df = pd.DataFrame(appointments)
    st.dataframe(appointments_df, use_container_width=True)

def view_reports():
    """Render the view reports page"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">View Patient Reports</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "doctor_dashboard"
        log_activity("navigation", "Returned to dashboard from view reports")
        st.experimental_rerun()
    
    # Patient search with autocomplete
    st.markdown('<h2 class="sub-header">Select Patient</h2>', unsafe_allow_html=True)
    
    patient_options = ["Select a patient"] + [f"{data['name']} ({email})" for email, data in st.session_state.patient_data.items()]
    selected_patient = st.selectbox("Patient", patient_options)
    
    if selected_patient != "Select a patient":
        email = selected_patient.split("(")[1].split(")")[0]
        patient_data = st.session_state.patient_data[email]
        log_activity("view", f"Viewed reports for patient: {patient_data['name']}")
        
        st.markdown(f'<h2 class="sub-header">Reports for {patient_data["name"]}</h2>', unsafe_allow_html=True)
        
        # Patient info card
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Patient Information</div>
            <p><strong>Name:</strong> {patient_data["name"]}</p>
            <p><strong>ID:</strong> {patient_data["id"]}</p>
            <p><strong>Email:</strong> {email}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Reports
        
                # Reports
        if patient_data["reports"]:
            for i, report in enumerate(patient_data["reports"]):
                with st.expander(f"{report['type']} - {report['date']}", expanded=i==0):
                    st.markdown(f"**Notes:** {report['notes']}")
                    
                    # Simulated report viewer
                    if report['type'] in ['X-ray', 'MRI', 'CT Scan']:
                        # Display a placeholder image for demonstration
                        st.image("https://img.icons8.com/color/240/000000/x-ray.png", 
                                use_column_width=True)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.button("Download Report", key=f"download_{i}")
                        with col2:
                            st.button("Share with Patient", key=f"share_{i}")
                    
                    # Add doctor's notes
                    st.text_area("Add Notes", key=f"notes_{i}", height=100)
                    if st.button("Save Notes", key=f"save_notes_{i}"):
                        st.success("Notes saved successfully!")
        else:
            st.info("No reports available for this patient")
            
        # Add new report button
        if st.button("Request New Report", key="request_report"):
            st.session_state.current_page = "request_report"
            st.session_state.selected_patient = email
            st.experimental_rerun()

def diagnosis_records():
    """Render the diagnosis records page"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">Patient Diagnosis Records</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "doctor_dashboard"
        log_activity("navigation", "Returned to dashboard from diagnosis records")
        st.experimental_rerun()
    
    # Patient selection
    st.markdown('<h2 class="sub-header">Select Patient</h2>', unsafe_allow_html=True)
    
    patient_options = ["Select a patient"] + [f"{data['name']} ({email})" for email, data in st.session_state.patient_data.items()]
    selected_patient = st.selectbox("Patient", patient_options)
    
    if selected_patient != "Select a patient":
        email = selected_patient.split("(")[1].split(")")[0]
        patient_data = st.session_state.patient_data[email]
        log_activity("view", f"Viewed diagnosis records for patient: {patient_data['name']}")
        
        st.markdown(f'<h2 class="sub-header">Diagnosis Records for {patient_data["name"]}</h2>', unsafe_allow_html=True)
        
        # Patient info card
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Patient Information</div>
            <p><strong>Name:</strong> {patient_data["name"]}</p>
            <p><strong>ID:</strong> {patient_data["id"]}</p>
            <p><strong>Email:</strong> {email}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Diagnosis records
        if patient_data["records"]:
            # Create a DataFrame for better display
            records_df = pd.DataFrame(patient_data["records"])
            
            # Add visualization
            st.markdown("### Diagnosis Timeline")
            
            # Simple chart for demonstration
            if len(records_df) > 1:
                chart_data = pd.DataFrame({
                    "Date": range(len(records_df)),
                    "Severity": [i % 5 + 1 for i in range(len(records_df))]  # Simulated severity
                })
                st.line_chart(chart_data.set_index("Date"))
            
            # Detailed records
            st.markdown("### Detailed Records")
            for i, record in enumerate(patient_data["records"]):
                with st.expander(f"Diagnosis on {record['date']}", expanded=i==0):
                    st.markdown(f"**Symptoms:** {record['symptoms']}")
                    st.markdown(f"**Diagnosis:** {record['diagnosis']}")
                    
                    # Add treatment plan (simulated)
                    st.markdown("**Treatment Plan:**")
                    st.markdown("1. Medication: Paracetamol 500mg twice daily")
                    st.markdown("2. Rest for 3-5 days")
                    st.markdown("3. Follow-up in 1 week")
                    
                    # Add notes
                    st.text_area("Add Notes", key=f"diag_notes_{i}", height=100)
                    if st.button("Save Notes", key=f"save_diag_notes_{i}"):
                        st.success("Notes saved successfully!")
        else:
            st.info("No diagnosis records available for this patient")
        
        # Add new diagnosis button
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Add New Diagnosis", key="add_diagnosis"):
                st.session_state.current_page = "add_diagnosis"
                st.session_state.selected_patient = email
                st.experimental_rerun()
        with col2:
            if st.button("Generate Report", key="generate_report"):
                with st.spinner("Generating comprehensive report..."):
                    time.sleep(1.5)  # Simulate report generation
                    st.success("Report generated successfully!")
                    st.download_button(
                        label="Download Report",
                        data="This is a simulated report for demonstration purposes.",
                        file_name=f"{patient_data['name']}_report.pdf",
                        mime="application/pdf"
                    )

def submit_feedback():
    """Render the submit feedback page"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">Submit Feedback</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "doctor_dashboard"
        log_activity("navigation", "Returned to dashboard from submit feedback")
        st.experimental_rerun()
    
    # Patient selection
    st.markdown('<h2 class="sub-header">Select Patient</h2>', unsafe_allow_html=True)
    
    patient_options = ["Select a patient"] + [f"{data['name']} ({email})" for email, data in st.session_state.patient_data.items()]
    selected_patient = st.selectbox("Patient", patient_options)
    
    if selected_patient != "Select a patient":
        email = selected_patient.split("(")[1].split(")")[0]
        patient_data = st.session_state.patient_data[email]
        
        st.markdown(f'<h2 class="sub-header">Submit Feedback for {patient_data["name"]}</h2>', unsafe_allow_html=True)
        
        # Feedback form
        with st.form("feedback_form"):
            feedback_type = st.selectbox("Feedback Type", [
                "Treatment Progress", 
                "Diagnosis Accuracy", 
                "Medication Effectiveness", 
                "Side Effects", 
                "Other"
            ])
            
            feedback = st.text_area("Feedback", height=150)
            
            # Rating
            rating = st.slider("Treatment Effectiveness", 1, 5, 3)
            
            # Follow-up needed
            follow_up = st.checkbox("Follow-up Required")
            
            if follow_up:
                follow_up_date = st.date_input("Follow-up Date", 
                                              datetime.datetime.now() + datetime.timedelta(days=7))
                follow_up_notes = st.text_area("Follow-up Notes")
            
            submitted = st.form_submit_button("Submit Feedback")
            if submitted:
                if not feedback:
                    st.error("Please provide feedback")
                else:
                    log_activity("feedback", f"Submitted feedback for patient: {patient_data['name']}")
                    with st.spinner("Submitting feedback..."):
                        time.sleep(0.5)  # Simulate submission delay
                        st.success("Feedback submitted successfully!")
                        
                        # Show follow-up confirmation if selected
                        if follow_up:
                            st.info(f"Follow-up scheduled for {follow_up_date.strftime('%B %d, %Y')}")

def patient_dashboard():
    """Render the patient dashboard"""
    if not check_auth("Patient"):
        return
    
    st.markdown('<h1 class="main-header">Patient Dashboard</h1>', unsafe_allow_html=True)
    
    # Welcome message with time-based greeting
    hour = datetime.datetime.now().hour
    greeting = "Good morning" if 5 <= hour < 12 else "Good afternoon" if 12 <= hour < 18 else "Good evening"
    
    if st.session_state.user_email in st.session_state.patient_data:
        patient_data = st.session_state.patient_data[st.session_state.user_email]
        st.markdown(f"### {greeting}, {patient_data['name']}")
        
        # Quick stats
        st.markdown("### Your Health Summary")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(label="Appointments", value="2")
        with col2:
            st.metric(label="Reports", value=len(patient_data["reports"]))
        with col3:
            st.metric(label="Medications", value="3")
        with col4:
            st.metric(label="Health Score", value="85%", delta="5%")
        
        # Cards
        st.markdown("### Quick Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="card">
                <div class="card-title">Check Symptoms</div>
                <p>Describe your symptoms for AI-powered analysis</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Check Symptoms", key="check_symptoms_btn"):
                st.session_state.current_page = "symptom_checker"
                log_activity("navigation", "Navigated to symptom checker from dashboard")
        
        with col2:
            st.markdown("""
            <div class="card">
                <div class="card-title">Upload Medical Report</div>
                <p>Upload your medical reports for doctor review</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Upload Report", key="upload_report_btn"):
                st.session_state.current_page = "upload_report"
                log_activity("navigation", "Navigated to upload report from dashboard")
        
        with col3:
            st.markdown("""
            <div class="card">
                <div class="card-title">View My History</div>
                <p>Access your diagnosis and treatment history</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button("View History", key="view_history_btn"):
                st.session_state.current_page = "view_history"
                log_activity("navigation", "Navigated to view history from dashboard")
        
        # Recent diagnosis
        st.markdown('<h2 class="sub-header">Recent Diagnosis</h2>', unsafe_allow_html=True)
        
        if patient_data["records"]:
            latest_record = patient_data["records"][0]
            st.markdown(f"""
            <div class="card">
                <div class="card-title">Diagnosis on {latest_record["date"]}</div>
                <p><strong>Symptoms:</strong> {latest_record["symptoms"]}</p>
                <p><strong>Diagnosis:</strong> {latest_record["diagnosis"]}</p>
                <p><strong>Next Steps:</strong> Follow up with your doctor in 7 days</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("No recent diagnosis available")
        
        # Upcoming appointments (simulated)
        st.markdown('<h2 class="sub-header">Upcoming Appointments</h2>', unsafe_allow_html=True)
        
        appointments = [
            {"Doctor": "Dr. Sharma", "Date": "Tomorrow, 10:00 AM", "Type": "Follow-up"},
            {"Doctor": "Dr. Patel", "Date": "Next Week, 2:00 PM", "Type": "Consultation"},
        ]
        
        appointments_df = pd.DataFrame(appointments)
        st.dataframe(appointments_df, use_container_width=True)
        
        # Book appointment button
        if st.button("Book New Appointment", key="book_appointment"):
            st.session_state.current_page = "book_appointment"
            st.experimental_rerun()

def symptom_checker():
    """Render the symptom checker page"""
    if not check_auth("Patient"):
        return
    
    st.markdown('<h1 class="main-header">Symptom Checker</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "patient_dashboard"
        log_activity("navigation", "Returned to dashboard from symptom checker")
        st.experimental_rerun()
    
    st.markdown('<h2 class="sub-header">Describe Your Symptoms</h2>', unsafe_allow_html=True)
    
    # Information card
    st.markdown("""
    <div class="info-msg">
        <strong>How it works:</strong> Our AI-powered symptom checker analyzes your symptoms and provides 
        possible diagnoses. This is not a substitute for professional medical advice. 
        Please consult with a healthcare provider for proper diagnosis and treatment.
    </div>
    """, unsafe_allow_html=True)
    
    # Symptom form
    with st.form("symptom_form"):
        # Common symptoms checkboxes
        st.markdown("### Common Symptoms")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            fever = st.checkbox("Fever")
            cough = st.checkbox("Cough")
            headache = st.checkbox("Headache")
            fatigue = st.checkbox("Fatigue")
        
        with col2:
            sore_throat = st.checkbox("Sore Throat")
            body_ache = st.checkbox("Body Ache")
            nausea = st.checkbox("Nausea")
            dizziness = st.checkbox("Dizziness")
        
        with col3:
            shortness_of_breath = st.checkbox("Shortness of Breath")
            chest_pain = st.checkbox("Chest Pain")
            abdominal_pain = st.checkbox("Abdominal Pain")
            rash = st.checkbox("Rash")
        
        # Duration
        st.markdown("### Duration")
        duration = st.radio("How long have you been experiencing these symptoms?", 
                           ["Less than 24 hours", "1-3 days", "4-7 days", "More than a week"])
        
        # Severity
        st.markdown("### Severity")
        severity = st.slider("Rate the severity of your symptoms", 1, 10, 5)
        
        # Additional symptoms
        st.markdown("### Additional Information")
        additional_symptoms = st.text_area("Describe any other symptoms or provide more details", height=100)
        
        # Submit button
        submitted = st.form_submit_button("Analyze Symptoms")
        
        if submitted:
            # Collect selected symptoms
            selected_symptoms = []
            if fever: selected_symptoms.append("Fever")
            if cough: selected_symptoms.append("Cough")
            if headache: selected_symptoms.append("Headache")
            if fatigue: selected_symptoms.append("Fatigue")
            if sore_throat: selected_symptoms.append("Sore Throat")
            if body_ache: selected_symptoms.append("Body Ache")
            if nausea: selected_symptoms.append("Nausea")
            if dizziness: selected_symptoms.append("Dizziness")
            if shortness_of_breath: selected_symptoms.append("Shortness of Breath")
            if chest_pain: selected_symptoms.append("Chest Pain")
            if abdominal_pain: selected_symptoms.append("Abdominal Pain")
            if rash: selected_symptoms.append("Rash")
            
            if not selected_symptoms and not additional_symptoms:
                st.error("Please select at least one symptom or provide additional information")
            else:
                log_activity("symptom_check", f"Analyzed symptoms: {', '.join(selected_symptoms)}")
                
                with st.spinner("Analyzing symptoms..."):
                    time.sleep(1.5)  # Simulate AI analysis
                    
                    # Determine diagnosis based on symptoms (simplified for demo)
                    diagnosis = "Unknown"
                    recommendation = ""
                    urgency = "low"
                    
                    if "Fever" in selected_symptoms and "Cough" in selected_symptoms:
                        diagnosis = "Possible Flu or Common Cold"
                        recommendation = "Rest, stay hydrated, and take over-the-counter fever reducers if needed."
                        urgency = "medium" if severity > 7 else "low"
                    elif "Headache" in selected_symptoms and "Nausea" in selected_symptoms:
                        diagnosis = "Possible Migraine"
                        recommendation = "Rest in a dark, quiet room. Consider over-the-counter pain relievers."
                        urgency = "medium" if severity > 8 else "low"
                    elif "Chest Pain" in selected_symptoms and "Shortness of Breath" in selected_symptoms:
                        diagnosis = "Possible Respiratory Issue"
                        recommendation = "This could be serious. Please consult a doctor immediately."
                        urgency = "high"
                    elif "Abdominal Pain" in selected_symptoms:
                        diagnosis = "Possible Digestive Issue"
                        recommendation = "Monitor symptoms. If pain is severe or persistent, consult a doctor."
                        urgency = "medium" if severity > 6 else "low"
                    else:
                        diagnosis = "Possible Minor Condition"
                        recommendation = "Monitor your symptoms. If they worsen or persist, consult a doctor."
                        urgency = "low"
                    
                    # Display diagnosis
                    if urgency == "high":
                        st.markdown("""
                        <div class="error-msg">
                            <strong>Urgent Medical Attention Recommended</strong><br>
                            Your symptoms suggest a condition that may require immediate medical attention.
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown(f"""
                    <div class="card">
                        <div class="card-title">Diagnosis Results</div>
                        <p><strong>Possible Condition:</strong> {diagnosis}</p>
                        <p><strong>Recommendation:</strong> {recommendation}</p>
                        <p><strong>Urgency:</strong> {urgency.title()}</p>
                        <p><em>Note: This is an AI-generated diagnosis and should not replace professional medical advice.</em></p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Add to patient records
                    if st.session_state.user_email in st.session_state.patient_data:
                        today = datetime.datetime.now().strftime("%b %d")
                        symptoms_text = ", ".join(selected_symptoms)
                        if additional_symptoms:
                            symptoms_text += f", {additional_symptoms}"
                        
                        st.session_state.patient_data[st.session_state.user_email]["records"].insert(0, {
                            "date": today,
                            "symptoms": symptoms_text,
                            "diagnosis": diagnosis
                        })
                    
                    # Offer next steps
                    st.markdown("### Next Steps")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("Book Doctor Appointment", key="book_doctor"):
                            st.session_state.current_page = "book_appointment"
                            st.experimental_rerun()
                    
                    with col2:
                        if st.button("Save to My Records", key="save_records"):
                            st.success("Diagnosis saved to your records!")

def upload_report():
    """Render the upload report page"""
    if not check_auth("Patient"):
        return
    
    st.markdown('<h1 class="main-header">Upload Medical Report</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "patient_dashboard"
        log_activity("navigation", "Returned to dashboard from upload report")
        st.experimental_rerun()
    
    st.markdown('<h2 class="sub-header">Upload X-ray / Medical Report</h2>', unsafe_allow_html=True)
    
    # Information card
    st.markdown("""
    <div class="info-msg">
        <strong>Supported file types:</strong> JPG, JPEG, PNG, PDF, DICOM<br>
        <strong>Maximum file size:</strong> 10MB
    </div>
    """, unsafe_allow_html=True)
    
    # Upload form
    with st.form("upload_form"):
        uploaded_file = st.file_uploader("Choose a file", 
                                        type=CONFIG["allowed_file_types"])
        
        report_type = st.selectbox("Report Type", [
            "X-ray", 
            "MRI", 
            "CT Scan", 
            "Blood Test", 
            "Ultrasound",
            "ECG/EKG",
            "Other"
        ])
        
        if report_type == "Other":
            other_type = st.text_input("Please specify")
        
        # Doctor selection
        st.markdown("### Share with Doctor")
        doctor_options = ["Select a doctor"] + [
            f"Dr. {email.split('@')[0].title()}" 
            for email, data in st.session_state.users.items() 
            if data["role"] == "Doctor"
        ]
        selected_doctor = st.selectbox("Doctor", doctor_options)
        
        notes = st.text_area("Additional Notes", height=100, 
                            placeholder="Describe any symptoms or context for this report")
        
        submitted = st.form_submit_button("Upload Report")
        
        if submitted:
            if uploaded_file is not None:
                # Validate file size (simulated)
                file_size_mb = 5  # Simulated file size
                if file_size_mb > CONFIG["max_upload_size_mb"]:
                    st.error(f"File size exceeds the maximum limit of {CONFIG['max_upload_size_mb']}MB")
                else:
                    log_activity("upload", f"Uploaded {report_type} report")
                    
                    with st.spinner("Uploading and processing report..."):
                        time.sleep(1.5)  # Simulate upload and processing
                        
                        # Add to patient reports
                        if st.session_state.user_email in st.session_state.patient_data:
                            today = datetime.datetime.now().strftime("%b %d")
                            actual_report_type = other_type if report_type == "Other" else report_type
                            
                            st.session_state.patient_data[st.session_state.user_email]["reports"].insert(0, {
                                "date": today,
                                "type": actual_report_type,
                                "notes": sanitize_input(notes)
                            })
                        
                        st.markdown("""
                        <div class="success-msg">
                            <strong>Success!</strong> Report submitted for diagnosis. A doctor will review your report soon.
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Show AI analysis for certain report types
                        if report_type in ["X-ray", "MRI", "CT Scan"]:
                            st.markdown("### AI Preliminary Analysis")
                            st.markdown("""
                            <div class="card">
                                <div class="card-title">Preliminary Findings</div>
                                <p>Our AI has analyzed your report and found no immediate concerns. 
                                A doctor will review your report for a complete diagnosis.</p>
                                <p><em>Note: This is an automated preliminary analysis and should not be 
                                considered a final diagnosis.</em></p>
                            </div>
                            """, unsafe_allow_html=True)
            else:
                st.error("Please upload a file")

def view_history():
    """Render the view history page"""
    if not check_auth("Patient"):
        return
    
    st.markdown('<h1 class="main-header">My Diagnosis History</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "patient_dashboard"
        log_activity("navigation", "Returned to dashboard from view history")
        st.experimental_rerun()
    
    if st.session_state.user_email in st.session_state.patient_data:
        patient_data = st.session_state.patient_data[st.session_state.user_email]
        
        # Patient info card
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Patient Information</div>
            <p><strong>Name:</strong> {patient_data["name"]}</p>
            <p><strong>ID:</strong> {patient_data["id"]}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Tabs for different history types
        tab1, tab2 = st.tabs(["Diagnosis History", "Reports History"])
        
        with tab1:
            st.markdown('<h2 class="sub-header">Diagnosis History</h2>', unsafe_allow_html=True)
            
            if patient_data["records"]:
                # Create a DataFrame for better display
                records_df = pd.DataFrame(patient_data["records"])
                records_df.columns = ["Date", "Symptoms", "Result"]
                
                # Add visualization
                if len(records_df) > 1:
                    st.markdown("### Health Trends")
                    chart_data = pd.DataFrame({
                        "Date": range(len(records_df)),
                        "Health Score": [75 + (i * 5) % 15 for i in range(len(records_df))]  # Simulated health score
                    })
                    st.line_chart(chart_data.set_index("Date"))
                
                # Detailed records
                st.markdown("### Detailed Records")
                for i, record in enumerate(patient_data["records"]):
                    with st.expander(f"Diagnosis on {record['date']}", expanded=i==0):
                        st.markdown(f"**Symptoms:** {record['symptoms']}")
                        st.markdown(f"**Diagnosis:** {record['diagnosis']}")
                        
                        # Add treatment plan (simulated)
                        st.markdown("**Recommended Treatment:**")
                        st.markdown("1. Medication: Paracetamol 500mg twice daily")
                        st.markdown("2. Rest for 3-5 days")
                        st.markdown("3. Follow-up in 1 week")
            else:
                st.info("No diagnosis history available")
        
        with tab2:
            st.markdown('<h2 class="sub-header">Reports History</h2>', unsafe_allow_html=True)
            
            if patient_data["reports"]:
                # Create a DataFrame for better display
                reports_df = pd.DataFrame(patient_data["reports"])
                
                # Display as a table
                st.dataframe(reports_df, use_container_width=True)
                
                # Detailed reports
                st.markdown("### Detailed Reports")
                for i, report in enumerate(patient_data["reports"]):
                    with st.expander(f"{report['type']} - {report['date']}", expanded=i==0):
                        st.markdown(f"**Type:** {report['type']}")
                        st.markdown(f"**Date:** {report['date']}")
                        st.markdown(f"**Notes:** {report['notes']}")
                        
                        # Simulated report viewer
                        if report['type'] in ['X-ray', 'MRI', 'CT Scan']:
                            # Display a placeholder image for demonstration
                            st.image("https://img.icons8.com/color/240/000000/x-ray.png", 
                                    use_column_width=True)
                            
                            st.download_button(
                                label="Download Report",
                                data="This is a simulated report for demonstration purposes.",
                                file_name=f"{report['type']}_{report['date'].replace(' ', '_')}.pdf",
                                mime="application/pdf"
                            )
            else:
                st.info("No reports history available")
        
        # Export options
        st.markdown("### Export Options")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Export All Records (PDF)", key="export_pdf"):
                with st.spinner("Generating PDF..."):
                    time.sleep(1)  # Simulate PDF generation
                    st.success("PDF generated successfully!")
                    st.download_button(
                        label="Download PDF",
                        data="This is a simulated PDF export for demonstration purposes.",
                        file_name=f"{patient_data['name']}_medical_records.pdf",
                        mime="application/pdf"
                    )
        
        with col2:
            if st.button("Export All Records (CSV)", key="export_csv"):
                with st.spinner("Generating CSV..."):
                    time.sleep(0.5)  # Simulate CSV generation
                    
                    # Create CSV data
                    if patient_data["records"]:
                        records_df = pd.DataFrame(patient_data["records"])
                        csv = records_df.to_csv(index=False)
                        
                        st.success("CSV generated successfully!")
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name=f"{patient_data['name']}_medical_records.csv",
                            mime="text/csv"
                        )
                    else:
                        st.error("No records available to export")

def about_page():
    """Render the about page"""
    st.markdown('<h1 class="main-header">About the System</h1>', unsafe_allow_html=True)
    
    if st.session_state.authenticated:
        # Back button
        if st.button("← Back to Dashboard", key="back_btn"):
            if st.session_state.user_role == "Doctor":
                st.session_state.current_page = "doctor_dashboard"
            else:
                st.session_state.current_page = "patient_dashboard"
            log_activity("navigation", "Returned to dashboard from about page")
            st.experimental_rerun()
    
    # About sections
    st.markdown("""
    <div class="card">
        <div class="card-title">AI in Healthcare Diagnosis</div>
        <p>Our platform leverages cutting-edge AI technologies to assist healthcare professionals in diagnosis:</p>
        <ul>
                        <li><strong>CheXNet:</strong> A deep learning algorithm that can detect pneumonia from chest X-rays with better accuracy than radiologists</li>
            <li><strong>MedBERT:</strong> A natural language processing model trained on medical literature to assist in diagnosis based on symptoms</li>
            <li><strong>PathAI:</strong> AI-powered pathology analysis for faster and more accurate disease detection</li>
            <li><strong>RetinAI:</strong> Deep learning for retinal image analysis to detect diabetic retinopathy and other eye conditions</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="card">
        <div class="card-title">Our Mission</div>
        <p>We are committed to revolutionizing healthcare through technology. Our mission is to:</p>
        <ul>
            <li>Improve diagnostic accuracy and reduce medical errors</li>
            <li>Enhance patient access to quality healthcare</li>
            <li>Reduce healthcare costs through efficient diagnosis</li>
            <li>Support healthcare professionals with advanced tools</li>
            <li>Ensure patient data privacy and security</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Team information
    st.markdown("""
    <div class="card">
        <div class="card-title">Our Team</div>
        <p>Our multidisciplinary team consists of healthcare professionals, AI researchers, and software engineers dedicated to improving healthcare outcomes.</p>
        
        <div style="display: flex; justify-content: space-between; flex-wrap: wrap;">
            <div style="width: 48%; margin-bottom: 15px;">
                <h4>Dr. Rajesh Kumar</h4>
                <p>Chief Medical Officer</p>
                <p>20+ years of experience in internal medicine</p>
            </div>
            <div style="width: 48%; margin-bottom: 15px;">
                <h4>Dr. Priya Sharma</h4>
                <p>Head of AI Research</p>
                <p>PhD in Machine Learning from IIT Delhi</p>
            </div>
            <div style="width: 48%; margin-bottom: 15px;">
                <h4>Vikram Singh</h4>
                <p>Lead Software Engineer</p>
                <p>Former tech lead at Microsoft Health</p>
            </div>
            <div style="width: 48%; margin-bottom: 15px;">
                <h4>Neha Patel</h4>
                <p>Data Privacy Officer</p>
                <p>Certified in Healthcare Information Security</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Technology stack
    st.markdown("""
    <div class="card">
        <div class="card-title">Technology Stack</div>
        <p>Our platform is built using cutting-edge technologies:</p>
        <ul>
            <li><strong>Frontend:</strong> Streamlit for interactive web interface</li>
            <li><strong>Backend:</strong> Python with FastAPI for scalable services</li>
            <li><strong>AI Models:</strong> TensorFlow and PyTorch for deep learning</li>
            <li><strong>Data Storage:</strong> HIPAA-compliant encrypted databases</li>
            <li><strong>Security:</strong> End-to-end encryption and OAuth 2.0 authentication</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Contact information
    st.markdown("""
    <div class="card">
        <div class="card-title">Contact Us</div>
        <p>We're here to help! Reach out to us with any questions or feedback:</p>
        <p><strong>Email:</strong> support@healthcareai.com</p>
        <p><strong>Phone:</strong> +91 1234567890</p>
        <p><strong>Address:</strong> 123 Innovation Park, Bangalore, India</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Version information
    st.markdown(f"""
    <div style="text-align: center; margin-top: 30px; color: #888;">
        <p>Version {CONFIG['version']} | © 2023 Healthcare AI Assistant</p>
    </div>
    """, unsafe_allow_html=True)

def book_appointment():
    """Render the book appointment page"""
    if not check_auth("Patient"):
        return
    
    st.markdown('<h1 class="main-header">Book Appointment</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state.current_page = "patient_dashboard"
        log_activity("navigation", "Returned to dashboard from book appointment")
        st.experimental_rerun()
    
    st.markdown('<h2 class="sub-header">Schedule a Doctor Appointment</h2>', unsafe_allow_html=True)
    
    # Appointment form
    with st.form("appointment_form"):
        # Doctor selection
        st.markdown("### Select Doctor")
        doctor_options = ["Select a doctor"] + [
            f"Dr. {email.split('@')[0].title()} - {data.get('specialty', 'General Physician')}" 
            for email, data in st.session_state.users.items() 
            if data["role"] == "Doctor"
        ]
        selected_doctor = st.selectbox("Doctor", doctor_options)
        
        # Appointment type
        appointment_type = st.selectbox("Appointment Type", [
            "Regular Checkup",
            "Follow-up",
            "New Consultation",
            "Test Results Review",
            "Vaccination",
            "Other"
        ])
        
        if appointment_type == "Other":
            other_type = st.text_input("Please specify")
        
        # Date and time
        col1, col2 = st.columns(2)
        with col1:
            appointment_date = st.date_input("Date", 
                                           min_value=datetime.datetime.now().date(),
                                           max_value=datetime.datetime.now().date() + datetime.timedelta(days=30))
        with col2:
            appointment_time = st.selectbox("Time", [
                "9:00 AM", "9:30 AM", "10:00 AM", "10:30 AM", "11:00 AM", "11:30 AM",
                "1:00 PM", "1:30 PM", "2:00 PM", "2:30 PM", "3:00 PM", "3:30 PM",
                "4:00 PM", "4:30 PM"
            ])
        
        # Reason for visit
        reason = st.text_area("Reason for Visit", height=100, 
                             placeholder="Briefly describe your symptoms or reason for the appointment")
        
        # Insurance information
        st.markdown("### Insurance Information")
        insurance_provider = st.selectbox("Insurance Provider", [
            "None/Self-pay",
            "National Health Insurance",
            "Aetna",
            "Cigna",
            "UnitedHealthcare",
            "Blue Cross Blue Shield",
            "Other"
        ])
        
        if insurance_provider != "None/Self-pay":
            insurance_id = st.text_input("Insurance ID")
        
        # Appointment mode
        appointment_mode = st.radio("Appointment Mode", ["In-person", "Video Consultation"])
        
        if appointment_mode == "Video Consultation":
            st.info("A link will be sent to your email before the appointment")
        
        # Submit button
        submitted = st.form_submit_button("Book Appointment")
        
        if submitted:
            if selected_doctor == "Select a doctor":
                st.error("Please select a doctor")
            elif not reason:
                st.error("Please provide a reason for your visit")
            else:
                log_activity("appointment", f"Booked appointment with {selected_doctor}")
                
                with st.spinner("Processing your appointment request..."):
                    time.sleep(1)  # Simulate processing delay
                    
                    st.markdown("""
                    <div class="success-msg">
                        <strong>Success!</strong> Your appointment has been scheduled.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Appointment details
                    actual_appointment_type = other_type if appointment_type == "Other" else appointment_type
                    
                    st.markdown(f"""
                    <div class="card">
                        <div class="card-title">Appointment Details</div>
                        <p><strong>Doctor:</strong> {selected_doctor}</p>
                        <p><strong>Date:</strong> {appointment_date.strftime('%B %d, %Y')}</p>
                        <p><strong>Time:</strong> {appointment_time}</p>
                        <p><strong>Type:</strong> {actual_appointment_type}</p>
                        <p><strong>Mode:</strong> {appointment_mode}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Reminder options
                    st.markdown("### Set Reminder")
                    reminder_options = st.multiselect("Reminder Options", [
                        "Email Reminder (24 hours before)",
                        "SMS Reminder (2 hours before)",
                        "Calendar Invite"
                    ])
                    
                    if st.button("Set Reminders"):
                        st.success("Reminders set successfully!")
                        
                        if "Calendar Invite" in reminder_options:
                            st.download_button(
                                label="Download Calendar Invite",
                                data="This is a simulated calendar invite file.",
                                file_name="appointment.ics",
                                mime="text/calendar"
                            )

def add_diagnosis():
    """Render the add diagnosis page"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">Add Diagnosis</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Records", key="back_btn"):
        st.session_state.current_page = "diagnosis_records"
        log_activity("navigation", "Returned to diagnosis records from add diagnosis")
        st.experimental_rerun()
    
    if "selected_patient" in st.session_state and st.session_state.selected_patient in st.session_state.patient_data:
        patient_email = st.session_state.selected_patient
        patient_data = st.session_state.patient_data[patient_email]
        
        st.markdown(f'<h2 class="sub-header">Add Diagnosis for {patient_data["name"]}</h2>', unsafe_allow_html=True)
        
        # Patient info card
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Patient Information</div>
            <p><strong>Name:</strong> {patient_data["name"]}</p>
            <p><strong>ID:</strong> {patient_data["id"]}</p>
            <p><strong>Email:</strong> {patient_email}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Diagnosis form
        with st.form("diagnosis_form"):
            # Symptoms
            symptoms = st.text_area("Symptoms", height=100, 
                                   placeholder="Enter patient symptoms")
            
            # Diagnosis
            diagnosis = st.text_area("Diagnosis", height=100,
                                    placeholder="Enter your diagnosis")
            
            # Treatment plan
            st.markdown("### Treatment Plan")
            
            # Medications
            st.markdown("#### Medications")
            col1, col2, col3 = st.columns(3)
            
            medications = []
            for i in range(3):  # Allow up to 3 medications
                with st.container():
                    med_name = st.text_input(f"Medication {i+1} Name", key=f"med_name_{i}")
                    if med_name:
                        med_dosage = st.text_input(f"Dosage", key=f"med_dosage_{i}")
                        med_frequency = st.selectbox(f"Frequency", [
                            "Once daily", 
                            "Twice daily", 
                            "Three times daily",
                            "Four times daily",
                            "Every 4 hours",
                            "Every 6 hours",
                            "Every 8 hours",
                            "As needed"
                        ], key=f"med_freq_{i}")
                        med_duration = st.text_input(f"Duration", key=f"med_duration_{i}", 
                                                   placeholder="e.g., 7 days, 2 weeks")
                        
                        if med_dosage and med_duration:
                            medications.append({
                                "name": med_name,
                                "dosage": med_dosage,
                                "frequency": med_frequency,
                                "duration": med_duration
                            })
            
            # Additional instructions
            additional_instructions = st.text_area("Additional Instructions", height=100,
                                                 placeholder="Enter any additional instructions or recommendations")
            
            # Follow-up
            follow_up_needed = st.checkbox("Follow-up Required")
            
            if follow_up_needed:
                follow_up_date = st.date_input("Follow-up Date", 
                                              datetime.datetime.now() + datetime.timedelta(days=7))
                follow_up_notes = st.text_area("Follow-up Notes")
            
            # Submit button
            submitted = st.form_submit_button("Save Diagnosis")
            
            if submitted:
                if not symptoms or not diagnosis:
                    st.error("Please enter both symptoms and diagnosis")
                else:
                    log_activity("diagnosis", f"Added diagnosis for patient: {patient_data['name']}")
                    
                    with st.spinner("Saving diagnosis..."):
                        time.sleep(0.5)  # Simulate saving delay
                        
                        # Add to patient records
                        today = datetime.datetime.now().strftime("%b %d")
                        
                        st.session_state.patient_data[patient_email]["records"].insert(0, {
                            "date": today,
                            "symptoms": sanitize_input(symptoms),
                            "diagnosis": sanitize_input(diagnosis)
                        })
                        
                        st.success("Diagnosis saved successfully!")
                        
                        # Show follow-up confirmation if selected
                        if follow_up_needed:
                            st.info(f"Follow-up scheduled for {follow_up_date.strftime('%B %d, %Y')}")
                        
                        # Generate prescription
                        if medications:
                            st.markdown("### Prescription Generated")
                            
                            prescription_text = f"""
                            **Doctor:** Dr. {st.session_state.user_email.split('@')[0].title()}
                            **Patient:** {patient_data['name']} (ID: {patient_data['id']})
                            **Date:** {today}
                            
                            **Medications:**
                            """
                            
                            for med in medications:
                                prescription_text += f"- {med['name']} {med['dosage']}, {med['frequency']} for {med['duration']}\n"
                            
                            if additional_instructions:
                                prescription_text += f"\n**Additional Instructions:**\n{additional_instructions}\n"
                            
                            if follow_up_needed:
                                prescription_text += f"\n**Follow-up:** {follow_up_date.strftime('%B %d, %Y')}"
                            
                            st.download_button(
                                label="Download Prescription",
                                data=prescription_text,
                                file_name=f"{patient_data['name']}_prescription_{today.replace(' ', '_')}.txt",
                                mime="text/plain"
                            )
    else:
        st.error("No patient selected or invalid patient")
        if st.button("Return to Dashboard"):
            st.session_state.current_page = "doctor_dashboard"
            st.experimental_rerun()

def request_report():
    """Render the request report page"""
    if not check_auth("Doctor"):
        return
    
    st.markdown('<h1 class="main-header">Request Medical Report</h1>', unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Reports", key="back_btn"):
        st.session_state.current_page = "view_reports"
        log_activity("navigation", "Returned to view reports from request report")
        st.experimental_rerun()
    
    if "selected_patient" in st.session_state and st.session_state.selected_patient in st.session_state.patient_data:
        patient_email = st.session_state.selected_patient
        patient_data = st.session_state.patient_data[patient_email]
        
        st.markdown(f'<h2 class="sub-header">Request Report for {patient_data["name"]}</h2>', unsafe_allow_html=True)
        
        # Patient info card
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Patient Information</div>
            <p><strong>Name:</strong> {patient_data["name"]}</p>
            <p><strong>ID:</strong> {patient_data["id"]}</p>
            <p><strong>Email:</strong> {patient_email}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Request form
        with st.form("request_form"):
            # Report type
            report_type = st.selectbox("Report Type", [
                "X-ray", 
                "MRI", 
                "CT Scan", 
                "Blood Test", 
                "Ultrasound",
                "ECG/EKG",
                "Other"
            ])
            
            if report_type == "Other":
                other_type = st.text_input("Please specify")
            
            # Body part/area (for imaging)
            if report_type in ["X-ray", "MRI", "CT Scan", "Ultrasound"]:
                body_part = st.selectbox("Body Part/Area", [
                    "Head/Brain",
                    "Chest/Lungs",
                    "Abdomen",
                    "Spine",
                    "Pelvis",
                    "Upper Extremity",
                    "Lower Extremity",
                    "Other"
                ])
                
                if body_part == "Other":
                    other_body_part = st.text_input("Please specify body part")
            
            # Test details (for blood tests)
            if report_type == "Blood Test":
                test_details = st.multiselect("Test Details", [
                    "Complete Blood Count (CBC)",
                    "Comprehensive Metabolic Panel (CMP)",
                    "Lipid Panel",
                    "Thyroid Function",
                    "Liver Function",
                    "Kidney Function",
                    "Glucose Test",
                    "Other"
                ])
                
                if "Other" in test_details:
                    other_test = st.text_input("Please specify test")
            
            # Clinical information
            clinical_info = st.text_area("Clinical Information", height=100,
                                        placeholder="Enter relevant clinical information or symptoms")
            
            # Urgency
            urgency = st.radio("Urgency", ["Routine", "Urgent", "STAT (Emergency)"])
            
            # Additional notes
            notes = st.text_area("Additional Notes", height=100)
            
            # Submit button
            submitted = st.form_submit_button("Send Request")
            
            if submitted:
                if not clinical_info:
                    st.error("Please provide clinical information")
                else:
                    log_activity("request", f"Requested {report_type} for patient: {patient_data['name']}")
                    
                    with st.spinner("Sending request..."):
                        time.sleep(0.5)  # Simulate sending delay
                        
                        st.markdown("""
                        <div class="success-msg">
                            <strong>Success!</strong> Report request has been sent to the patient.
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Request details
                        actual_report_type = other_type if report_type == "Other" else report_type
                        
                        st.markdown(f"""
                        <div class="card">
                            <div class="card-title">Request Details</div>
                            <p><strong>Report Type:</strong> {actual_report_type}</p>
                            <p><strong>Urgency:</strong> {urgency}</p>
                            <p><strong>Requested By:</strong> Dr. {st.session_state.user_email.split('@')[0].title()}</p>
                            <p><strong>Request Date:</strong> {datetime.datetime.now().strftime("%b %d, %Y")}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Notification options
                        st.markdown("### Notification Options")
                        notification_options = st.multiselect("Notify me when", [
                            "Patient views the request",
                            "Patient uploads the report",
                            "Report is ready for review"
                        ])
                        
                        if st.button("Set Notifications"):
                            st.success("Notification preferences saved!")
    else:
        st.error("No patient selected or invalid patient")
        if st.button("Return to Dashboard"):
            st.session_state.current_page = "doctor_dashboard"
            st.experimental_rerun()
# Add these helper functions before the initialize_session_state function

def log_activity(activity_type, description):
    """Log user activity"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = st.session_state.user_email if st.session_state.authenticated else "Guest"
    
    st.session_state.activity_log.append({
        "timestamp": timestamp,
        "user": user,
        "type": activity_type,
        "description": description
    })

def sanitize_input(text):
    """Basic sanitization of user input"""
    if text:
        # Remove any potentially harmful HTML/script tags
        text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text

def check_auth(required_role=None):
    """Check if user is authenticated and has the required role"""
    if not st.session_state.authenticated:
        st.warning("Please log in to access this page")
        st.session_state.current_page = "login"
        st.experimental_rerun()
        return False
    
    if required_role and st.session_state.user_role != required_role:
        st.error(f"Access denied. This page is only for {required_role}s.")
        
        # Redirect to appropriate dashboard
        if st.session_state.user_role == "Doctor":
            st.session_state.current_page = "doctor_dashboard"
        else:
            st.session_state.current_page = "patient_dashboard"
        
        st.experimental_rerun()
        return False
    
    return True

def apply_custom_css():
    """Apply custom CSS styling"""
    st.markdown("""
    <style>
        /* Main headers */
        .main-header {
            color: #2c3e50;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            text-align: center;
        }
        
        /* Sub headers */
        .sub-header {
            color: #34495e;
            font-size: 1.8rem;
            font-weight: 600;
            margin-top: 1.5rem;
            margin-bottom: 1rem;
        }
        
        /* Cards */
        .card {
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .card-title {
            color: #2c3e50;
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1rem;
            border-bottom: 1px solid #eee;
            padding-bottom: 0.5rem;
        }
        
        /* Success message */
        .success-msg {
            background-color: #d4edda;
            color: #155724;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        /* Error message */
        .error-msg {
            background-color: #f8d7da;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        /* Info message */
        .info-msg {
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        /* Warning message */
        .warning-msg {
            background-color: #fff3cd;
            color: #856404;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        /* Sidebar styling */
        .sidebar-content {
            padding: 1rem;
        }
        
        /* Button styling */
        .stButton>button {
            width: 100%;
        }
    </style>
    """, unsafe_allow_html=True)
def initialize_session_state():
    """Initialize session state variables"""
    # Authentication state
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if "user_email" not in st.session_state:
        st.session_state.user_email = ""
    
    if "user_role" not in st.session_state:
        st.session_state.user_role = ""
    
    # Current page
    if "current_page" not in st.session_state:
        st.session_state.current_page = "login"
    
    # Selected patient (for doctor view)
    if "selected_patient" not in st.session_state:
        st.session_state.selected_patient = None
    
    # Sample users data (in a real app, this would be in a database)
    if "users" not in st.session_state:
        st.session_state.users = {
            "doctor@example.com": {
                "password": "doctor123",
                "role": "Doctor",
                "name": "Dr. Smith",
                "specialty": "General Physician"
            },
            "doctor2@example.com": {
                "password": "doctor123",
                "role": "Doctor",
                "name": "Dr. Johnson",
                "specialty": "Cardiologist"
            },
            "patient@example.com": {
                "password": "patient123",
                "role": "Patient",
                "name": "John Doe"
            },
            "patient2@example.com": {
                "password": "patient123",
                "role": "Patient",
                "name": "Jane Smith"
            }
        }
    
    # Sample patient data (in a real app, this would be in a database)
    if "patient_data" not in st.session_state:
        st.session_state.patient_data = {
            "patient@example.com": {
                "name": "John Doe",
                "id": "P12345",
                "age": 35,
                "gender": "Male",
                "records": [
                    {
                        "date": "Nov 15",
                        "symptoms": "Fever, cough, fatigue",
                        "diagnosis": "Common cold"
                    },
                    {
                        "date": "Oct 03",
                        "symptoms": "Headache, dizziness",
                        "diagnosis": "Migraine"
                    }
                ],
                "reports": [
                    {
                        "date": "Nov 10",
                        "type": "Blood Test",
                        "notes": "Routine checkup"
                    },
                    {
                        "date": "Sep 25",
                        "type": "X-ray",
                        "notes": "Chest X-ray for persistent cough"
                    }
                ]
            },
            "patient2@example.com": {
                "name": "Jane Smith",
                "id": "P67890",
                "age": 42,
                "gender": "Female",
                "records": [
                    {
                        "date": "Nov 05",
                        "symptoms": "Joint pain, stiffness",
                        "diagnosis": "Arthritis"
                    }
                ],
                "reports": [
                    {
                        "date": "Nov 01",
                        "type": "MRI",
                        "notes": "Knee examination"
                    }
                ]
            }
        }
    
    # Activity log
    if "activity_log" not in st.session_state:
        st.session_state.activity_log = []


# Main app
def main():
    # Initialize session state
    initialize_session_state()
    
    # Apply custom CSS
    apply_custom_css()
    
    # Sidebar
    render_navigation()
    
    # Render the appropriate page based on the current page in session state
    if st.session_state.current_page == "login":
        login_page()
    elif st.session_state.current_page == "doctor_dashboard":
        doctor_dashboard()
    elif st.session_state.current_page == "patient_dashboard":
        patient_dashboard()
    elif st.session_state.current_page == "view_reports":
        view_reports()
    elif st.session_state.current_page == "diagnosis_records":
        diagnosis_records()
    elif st.session_state.current_page == "submit_feedback":
        submit_feedback()
    elif st.session_state.current_page == "symptom_checker":
        symptom_checker()
    elif st.session_state.current_page == "upload_report":
        upload_report()
    elif st.session_state.current_page == "view_history":
        view_history()
    elif st.session_state.current_page == "about":
        about_page()
    elif st.session_state.current_page == "book_appointment":
        book_appointment()
    elif st.session_state.current_page == "add_diagnosis":
        add_diagnosis()
    elif st.session_state.current_page == "request_report":
        request_report()

if __name__ == "__main__":
    main()