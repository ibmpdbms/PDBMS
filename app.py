import subprocess
import sys
def install_requirements():
    try:
        import flask  # test import for a core dependency
    except ImportError:
        print("🔧 Installing dependencies from requirements.txt...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully!")

install_requirements()

import os
from dotenv import load_dotenv
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, send_file, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from zoneinfo import ZoneInfo
from helpers import apology, login_required
import uuid
from fpdf import FPDF
import tempfile
from ibm_watson import NaturalLanguageUnderstandingV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_watson.natural_language_understanding_v1 import Features, KeywordsOptions
formatted_time = datetime.now(ZoneInfo("Asia/Kolkata"))
now_in_india = formatted_time.strftime("%Y-%m-%d %H:%M:%S %Z") 
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config['UPLOAD_FOLDER'] = "uploads"
db = SQL("sqlite:///data.db")
app.secret_key = os.getenv("SECRET_KEY")
load_dotenv()

@app.route("/")
@login_required
def index():
    return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    msg = request.args.get("msg")
    if msg:
        flash(msg)

    if request.method == "POST":
        username = request.form.get("username").lower().strip()
        password = request.form.get("password")

        # Basic checks
        if not username:
            return apology("must provide username", 403)
        if not password:
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check credentials
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Invalid username and/or password", 403)

        # Extra protection for admin login
        if rows[0]["role"] == "admin" and username != "admin":
            return apology("Unauthorized access attempt", 403)

        # Save session
        session["user_id"] = rows[0]["id"]
        session["role"] = rows[0]["role"]

        # If patient, fetch patient_code
        if rows[0]["role"] == "patient":
            code = db.execute("SELECT patient_code FROM records WHERE patient_name = ?", username)
            if code:
                session["patient_code"] = code[0]["patient_code"]
            else:
                session["patient_code"] = None

        # Redirect based on role
        if rows[0]["role"] == "admin":
            return redirect("/admin_dashboard")
        elif rows[0]["role"] == "staff":
            return redirect("/staff_dashboard")
        elif rows[0]["role"] == "patient":
            return redirect("/patient_dashboard")

    return render_template("login.html")



@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_pw():
    if request.method == "POST":
        curr_pw = request.form.get("curr_pw")
        new_pw = request.form.get("new-password")
        confirmation_new_pw = request.form.get("confirmation-new-pw")

        if not curr_pw:
            return apology(f"{session['role'].capitalize()} must provide old password")
        if not new_pw:
            return apology("Must Provide New Password")
        if not confirmation_new_pw:
            return apology("Must Provide Confirmation Password")

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        stored_hash = rows[0]["hash"]

        if not check_password_hash(stored_hash, curr_pw):
            return apology("Current Password is Incorrect")

        if new_pw != confirmation_new_pw:
            return apology("Passwords Do not Match!")

        if check_password_hash(stored_hash, new_pw):
            return apology("New password cannot be the same as the old password")

        hash = generate_password_hash(new_pw)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])

        flash("✅ Password Changed Successfully! Please log in again.")
        session.clear()
        return redirect(url_for("login", msg="Password changed successfully"))
    else:
        return render_template("change_password.html")


@app.route("/confirm_delete/<patient_code>")
@login_required
def confirm_delete(patient_code):
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)

    # Fetch patient details with user info
    patient = db.execute("""
        SELECT r.*, u.email, u.phone_number
        FROM records r
        LEFT JOIN users u ON LOWER(u.username) = LOWER(r.patient_name)
        WHERE r.patient_code = ?
    """, patient_code)

    if not patient:
        return apology("Patient not found", 404)

    return render_template("confirm_delete.html", patient=patient[0])





@app.route("/delete_patient/<patient_code>", methods=["POST"])
@login_required
def delete_patient(patient_code):
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)

    confirm_code = request.form.get("confirm_code")

    if confirm_code != patient_code:
        flash("❌ Patient code mismatch. Deletion cancelled.")
        return redirect(f"/confirm_delete/{patient_code}")

    db.execute("DELETE FROM records WHERE patient_code = ?", patient_code)
    flash("✅ Patient record deleted successfully.")
    return redirect("/staff_dashboard")


@app.route("/staff_dashboard")
@login_required
def staff_dashboard():
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)

    return render_template("staff_dashboard.html")

@app.route("/patient_dashboard")
@login_required
def patient_dashboard():
    if session.get("role") != "patient":
        return apology("Access Denied", 403)

    # Ensure patient has a linked patient_code
    patient_code = session.get("patient_code")
    if not patient_code:
        flash("No patient records linked. Please contact hospital staff.")
        return render_template("patient_dashboard.html", records=[])

    # Fetch records using patient_code
    records = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)

    return render_template("patient_dashboard.html", records=records)



@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if session.get("role") != "admin":
        return apology("Access Denied", 403)
    return render_template("admin_dashboard.html")

@app.route("/add_patient", methods=["GET", "POST"])
@login_required
def add_patient():
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)
    
    if request.method == "POST":
        patient_name = request.form.get("patient_name").strip().lower()
        patient_code = str(uuid.uuid4())[:8]  # Generate unique short code

        db.execute("""
            INSERT INTO records (patient_name, blood_group, weight, height,
                                 allergies, past_treatments, past_diseases,
                                 doctor_name, room_number, past_doctor_name,
                                 insurance_company, doctor_notes,patient_code,date,age,emergency_contact_name, emergency_contact,patient_contact_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
           patient_name,
           request.form.get("blood_group"),
           request.form.get("weight"),
           request.form.get("height"),
           request.form.get("allergies"),
           request.form.get("past_treatments"),
           request.form.get("past_diseases"),
           request.form.get("doctor_name").strip().upper(),
           request.form.get("room_number"),
           request.form.get("past_doctor_name").strip().upper(),
           request.form.get("insurance_company").strip().upper(),
           request.form.get("doctor_notes"),
           patient_code,
           now_in_india,
           request.form.get("age"),
           request.form.get("emergency_contact_name"),
           request.form.get("emergency_contact"),
           request.form.get("patient_contact_number")
        )
        flash(f"Patient record added successfully! Patient Code: {patient_code}")
        return redirect("/staff_dashboard")
    
    return render_template("add_patient.html")

@app.route("/update_patient/<string:patient_code>", methods=["GET", "POST"])
@login_required
def update_patient(patient_code):
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)

    # Fetch patient record
    patient = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)
    if not patient:
        return apology("Patient not found", 404)
    patient = patient[0]

    if request.method == "POST":
        # Update record
        db.execute("""
            UPDATE records
            SET patient_name = ?, blood_group = ?, weight = ?, height = ?,
                allergies = ?, past_treatments = ?, past_diseases = ?,
                doctor_name = ?, room_number = ?, past_doctor_name = ?,
                insurance_company = ?, doctor_notes = ?,
                age = ?, emergency_contact_name = ?, emergency_contact = ?, patient_contact_number = ?
            WHERE patient_code = ?
        """,
           request.form.get("patient_name").strip().lower(),
           request.form.get("blood_group"),
           request.form.get("weight"),
           request.form.get("height"),
           request.form.get("allergies"),
           request.form.get("past_treatments"),
           request.form.get("past_diseases"),
           request.form.get("doctor_name").strip().upper(),
           request.form.get("room_number"),
           request.form.get("past_doctor_name").strip().upper(),
           request.form.get("insurance_company").strip().upper(),
           request.form.get("doctor_notes"),
           request.form.get("age"),
           request.form.get("emergency_contact_name"),
           request.form.get("emergency_contact"),
           request.form.get("patient_contact_number"),
           patient_code
        )

        flash("✅ Patient record updated successfully!")
        return redirect(f"/patient_detail/{patient_code}")

    return render_template("update_patient.html", patient=patient)



@app.route("/patient_detail/<string:patient_code>")
@login_required
def patient_detail(patient_code):
    if session.get("role") not in ["staff", "admin", "patient"]:
        return apology("Access Denied", 403)

    patient = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)

    if not patient:
        return apology("Patient record not found", 404)

    # if patient, make sure they're only accessing their own record
    if session["role"] == "patient" and patient_code != session.get("patient_code"):
        return apology("Access Denied", 403)

    return render_template("patient_detail.html", patient=patient[0])


@app.route("/search_patient")
@login_required
def search_patient():
    if session.get("role") not in ["staff", "admin"]:
        return apology("Access Denied", 403)

    # Render the template that contains the search UI
    return render_template("search_patient.html")


@app.route("/api/search_patient")
@login_required
def api_search_patient():
    if session.get("role") not in ["staff", "admin"]:
        return {"error": "Access Denied"}, 403
    
    query = request.args.get("q", "").strip()
    if query:
        patients = db.execute("""
            SELECT patient_name, room_number, patient_code
            FROM records
            WHERE patient_name LIKE ? OR room_number LIKE ?
            ORDER BY patient_name ASC
        """, f"%{query}%", f"%{query}%")
    else:
        patients = db.execute("""
            SELECT patient_name, room_number, patient_code
            FROM records
            ORDER BY patient_name ASC
        """)

    return {"patients": patients}




@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username").strip()
        email = request.form.get("email").lower().strip()
        phone_number = request.form.get("phone_number").strip()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validation
        if not username:
            return apology("Must provide Username")
        if not email:
            return apology("Must provide Email")
        if not phone_number:
            return apology("Must provide Phone Number")
        if not password:
            return apology("Must provide Password")
        if not confirmation:
            return apology("Must provide Confirmation")
        if password != confirmation:
            return apology("Passwords don't match!")
        if username.lower() in ["admin", "administrator", "root"]:
            return apology("This username is reserved. Please choose another.")

        # Uniqueness checks
        if db.execute("SELECT id FROM users WHERE email = ?", email):
            return apology("This Email is already registered.")
        if db.execute("SELECT id FROM users WHERE phone_number = ?", phone_number):
            return apology("This Phone Number is already registered.")

        # Hash password and generate UUID
        hash = generate_password_hash(password)
        user_uuid = str(uuid.uuid4())[:8]

        try:
            new_user = db.execute(
                "INSERT INTO users (username, hash, role, uuid, email, phone_number) VALUES (?, ?, ?, ?, ?, ?)",
                username, hash, "patient", user_uuid, email, phone_number
            )
        except:
            return apology("This Username already exists. Please try another one")

        # Store session
        session["user_id"] = new_user
        session["role"] = "patient"
        session["patient_code"] = None

        flash(f"✅ Patient registered successfully! UUID: {user_uuid}")
        return redirect("/patient_dashboard")



@app.route("/register_staff", methods=["GET", "POST"])
@login_required
def register_staff():
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    if request.method == "POST":
        username = request.form.get("username").lower().strip()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Basic validations
        if not username:
            return apology("Must provide username")
        if not password or not confirmation:
            return apology("Must provide and confirm password")
        if password != confirmation:
            return apology("Passwords do not match")

        # Block reserved admin username
        if username == "admin":
            return apology("This username is reserved for administrators")

        hash = generate_password_hash(password)
        staff_uuid = str(uuid.uuid4())[:8]  # short unique ID

        try:
            db.execute(
                "INSERT INTO users (username, hash, role, uuid) VALUES (?, ?, ?, ?)",
                username, hash, "staff", staff_uuid
            )
        except:
            return apology("Username already exists")

        flash(f"✅ Staff account created! UUID: {staff_uuid}")
        return redirect("/admin_dashboard")

    return render_template("register_staff.html")


@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/manage_patients")
@login_required
def manage_patients():
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    patients = db.execute("""
        SELECT u.id, u.username, u.uuid, u.email, u.phone_number, r.patient_code
        FROM users u
        LEFT JOIN records r ON LOWER(u.username) = LOWER(r.patient_name)
        WHERE u.role = 'patient'
    """)
    return render_template("manage_patients.html", patients=patients)



@app.route("/manage_staff")
@login_required
def manage_staff():
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    staff = db.execute("SELECT id, username, role, uuid FROM users WHERE role = 'staff'")
    return render_template("manage_staff.html", staff=staff)

@app.route("/link_patient/<int:user_id>", methods=["GET", "POST"])
@login_required
def link_patient(user_id):
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return apology("User not found", 404)

    user = user[0]

    if request.method == "POST":
        patient_code = request.form.get("patient_code")

        # Check if patient record exists and isn't already linked
        record = db.execute("""
            SELECT r.patient_code, r.patient_name
            FROM records r
            LEFT JOIN users u 
                ON TRIM(LOWER(r.patient_name)) = TRIM(LOWER(u.username))
            WHERE r.patient_code = ?
        """, patient_code)

        if not record:
            flash("❌ Invalid patient code selected.")
            return redirect(f"/link_patient/{user_id}")

        # Prevent linking if already tied to another user
        already_linked = db.execute("""
            SELECT 1 FROM records r
            JOIN users u ON TRIM(LOWER(r.patient_name)) = TRIM(LOWER(u.username))
            WHERE r.patient_code = ?
        """, patient_code)

        if already_linked:
            flash("⚠️ This patient record is already linked to another account.")
            return redirect(f"/link_patient/{user_id}")

        # Link by updating patient_name to exact username
        db.execute("""
            UPDATE records 
            SET patient_name = ?
            WHERE patient_code = ?
        """, user["username"].strip().lower(), patient_code)

        flash(f"✅ Linked patient record {patient_code} to {user['username']}.")
        return redirect("/manage_patients")

    # Show only unlinked records
    unlinked = db.execute("""
        SELECT r.patient_code, r.patient_name
        FROM records r
        LEFT JOIN users u 
            ON TRIM(LOWER(r.patient_name)) = TRIM(LOWER(u.username))
        WHERE u.id IS NULL
    """)

    return render_template("link_patient.html", user=user, unlinked=unlinked)


@app.route("/customer_support")
def customer_support():
    return render_template("customer_support.html")

@app.route("/confirm_delete_user/<int:user_id>")
@login_required
def confirm_delete_user(user_id):
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    # Fetch user
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return apology("User not found", 404)
    user = user[0]

    # Fetch linked patient (if any)
    linked_patient = db.execute("""
        SELECT r.patient_code
        FROM records r
        WHERE TRIM(LOWER(r.patient_name)) = TRIM(LOWER(?))
    """, user["username"])

    return render_template(
        "confirm_delete_user.html",
        user=user,
        linked_patient=linked_patient[0] if linked_patient else None,
        referrer=request.referrer or url_for("admin_dashboard")
    )

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if session.get("role") != "admin":
        return apology("Access Denied", 403)

    confirm_uuid = request.form.get("confirm_uuid")
    next_url = request.form.get("next")
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return apology("User not found", 404)

    if confirm_uuid != user[0]["uuid"]:
        flash("❌ UUID mismatch. Deletion cancelled.")
        return redirect(f"/confirm_delete_user/{user_id}")

    db.execute("DELETE FROM users WHERE id = ?", user_id)
    flash(f"✅ User account '{user[0]['username']}' deleted successfully.")
    return redirect(next_url or url_for("admin_dashboard"))


@app.context_processor
def inject_user():
    try:
        if "user_id" in session:
            user = db.execute("SELECT username, role FROM users WHERE id = ?", session["user_id"])
            if user:
                return {"username": user[0]["username"], "role": user[0]["role"]}
    except:
        pass
    return {}


# Setup IBM Watson
authenticator = IAMAuthenticator(os.getenv('NLU_API_KEY'))
nlu = NaturalLanguageUnderstandingV1(
    version='2023-08-06',
        authenticator=authenticator
        )
nlu.set_service_url(os.getenv('NLU_URL'))

def calculate_bmi(weight, height_cm):
    try:
        height_m = float(height_cm) / 100
        bmi = round(float(weight) / (height_m ** 2), 2)
    except:
        return None, "Invalid Data"

    if bmi < 18.5:
            category = "Underweight"
    elif bmi < 25:
            category = "Normal"
    elif bmi < 30:
            category = "Overweight"
    else:
        category = "Obese"
    return bmi, category

def interpret_recovery(notes: str) -> str:
    """AI-like interpretation of recovery progress based on doctor's notes."""
    text = notes.lower()

    positive_signals = ["stable", "improving", "recovering", "better", "normal"]
    negative_signals = ["worsening", "critical", "unstable", "decline", "deteriorating"]
    neutral_signals  = ["no change", "maintained", "unchanged"]

    if any(word in text for word in positive_signals):
        return "AI interpretation: Patient is improving/recovering "
    elif any(word in text for word in negative_signals):
        return "AI interpretation: Patient condition may be worsening"
    elif any(word in text for word in neutral_signals):
        return "AI interpretation: No significant improvement observed"
    else:
        return "AI interpretation: Condition requires continued monitoring"


@app.route("/download_health_card/<string:patient_code>")
@login_required
def download_health_card(patient_code):
    # Ensure correct Access
    if session["role"] == "patient" and patient_code != session.get("patient_code"):
        return apology("Access Denied", 403)

    patient = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)
    if not patient:
        return apology("Patient record not found", 404)
    patient = patient[0]

    # 🔹 Gather current notes for AI
    current_notes = ", ".join(filter(None, [
        patient.get('allergies'),
        patient.get('doctor_notes')
    ]))

    current_factors = set()
    if current_notes and len(current_notes.split()) > 3:  # enough text for Watson
        try:
            analysis = nlu.analyze(
                text=current_notes,
                features=Features(keywords=KeywordsOptions(limit=5))
            ).get_result()

            key_terms = {kw["text"] for kw in analysis.get("keywords", [])}
            blacklist = {
                "none", "n/a", "last", "patient", "routine",
                "check", "ago", "hours", "drip", "seen", "stable", "hour", "discharge"
            }
            current_factors = {
                term for term in key_terms
                if term.lower() not in blacklist and not any(c.isdigit() for c in term)
            }
        except Exception as e:
            print("Watson NLU error:", e)

    # ✅ Always include allergy as a fallback current factor
    if patient.get("allergies") and patient["allergies"].lower() not in {"none", "n/a"}:
        current_factors.add(patient["allergies"])

    # 🔹 Past factors from history
    past_factors = list(filter(None, [
        patient.get('past_diseases'),
        patient.get('past_treatments')
    ]))

    # 🔹 AI interpretation from doctor notes
    doc_notes = (patient.get('doctor_notes') or "").lower()
    if any(word in doc_notes for word in ["stable", "recovering", "improving"]):
        interpretation = "Patient is improving/recovering "
    elif any(word in doc_notes for word in ["critical", "worsening", "deteriorating"]):
        interpretation = "Patient condition may be worsening "
    elif doc_notes.strip():
        interpretation = "Condition requires monitoring "
    else:
        interpretation = "No recent doctor notes available "

    # 🔹 BMI Calculation
    bmi, bmi_category = calculate_bmi(patient["weight"], patient["height"])
    # 🔹 Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 3, f"Generated on: {now_in_india}", ln=True, align='C')  # align right
    pdf.ln(2)
    pdf.image('static/impulse.jpg', x=20, y=15, w=35)   # Adjust path and size
    pdf.image('static/8bit.jpg', x=160, y=15, w=35)  # Adjust x to place it right

# 🔹 Add Title after leaving space
    pdf.set_xy(10, 50)   # Move cursor down after logos
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, f"Digital Health Card - {patient['patient_code']}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, f"Patient Name: {patient['patient_name']}")
    pdf.multi_cell(0, 10, f"Blood Group: {patient['blood_group']}")
    pdf.multi_cell(0, 10, f"Weight: {patient['weight']} kg")
    pdf.multi_cell(0, 10, f"Height: {patient['height']} cm")
    if bmi:
        pdf.multi_cell(0, 10, f"BMI: {bmi} ({bmi_category})")
    pdf.multi_cell(0, 10, f"Doctor: {patient['doctor_name']}")
    pdf.multi_cell(0, 10, f"Room Number: {patient['room_number']}")
    pdf.multi_cell(0, 10, f"Insurance: {patient['insurance_company']}")

    if current_factors:
        pdf.multi_cell(0, 10, f"Current Health Factors: {', '.join(current_factors)}")
    if past_factors:
        pdf.multi_cell(0, 10, f"Past Health Factors: {', '.join(past_factors)}")

    pdf.multi_cell(0, 10, f"Doctor Notes: {patient.get('doctor_notes', 'N/A')}")
    pdf.multi_cell(0, 10, f"AI Interpretation: {interpretation}")
    pdf.ln(10)
    pdf.image('static/impulse.jpg', x=20, y=pdf.get_y(), w=35)
    pdf.image('static/8bit.jpg', x=160, y=pdf.get_y(), w=35)

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf.output(temp_file.name)

    return send_file(temp_file.name, as_attachment=True,
                     download_name=f"{patient_code}_{patient['patient_name']}_health_card.pdf")

if __name__ == "__main__":
    app.run(debug=True, port=5000)