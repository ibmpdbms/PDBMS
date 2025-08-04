import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, send_file
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from zoneinfo import ZoneInfo
import pandas as pd
from helpers import apology, login_required
import time
import uuid

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config['UPLOAD_FOLDER'] = "uploads"
db = SQL("sqlite:///data.db")

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

        if not username:
            return apology("must provide username", 403)
        if not password:
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        session["role"] = rows[0]["role"]

        # If patient, also fetch patient_code
        if rows[0]["role"] == "patient":
            code = db.execute("SELECT patient_code FROM records WHERE patient_name = ?", username)
            if code:
                session["patient_code"] = code[0]["patient_code"]
            else:
                session["patient_code"] = None

        # Redirect
        # Redirect based on role
        if rows[0]["role"] == "admin":
            return redirect("/admin_dashboard")
        elif rows[0]["role"] == "staff":
            return redirect("/staff_dashboard")
        elif rows[0]["role"] == "patient":
            return redirect("/patient_dashboard")


    return render_template("login.html")

@app.route("/confirm_delete/<patient_code>")
@login_required
def confirm_delete(patient_code):
    if session.get("role") not in ["staff", "admin"]:
        return apology("access denied", 403)

    patient = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)
    if not patient:
        return apology("Patient not found", 404)

    return render_template("confirm_delete.html", patient=patient[0])


@app.route("/delete_patient/<patient_code>", methods=["POST"])
@login_required
def delete_patient(patient_code):
    if session.get("role") not in ["staff", "admin"]:
        return apology("access denied", 403)

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
        return apology("access denied", 403)

    return render_template("staff_dashboard.html")

@app.route("/patient_dashboard")
@login_required
def patient_dashboard():
    if session.get("role") != "patient":
        return apology("access denied", 403)

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
        return apology("access denied", 403)
    return render_template("admin_dashboard.html")

@app.route("/add_patient", methods=["GET", "POST"])
@login_required
def add_patient():
    if session.get("role") not in ["staff", "admin"]:
        return apology("access denied", 403)
    
    if request.method == "POST":
        patient_name = request.form.get("patient_name").strip().lower()
        patient_code = str(uuid.uuid4())[:8]  # Generate unique short code

        db.execute("""
            INSERT INTO records (patient_name, blood_group, weight, height,
                                 allergies, past_treatments, past_diseases,
                                 doctor_name, room_number, past_doctor_name,
                                 insurance_company, patient_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
           patient_code
        )
        flash(f"Patient record added successfully! Patient Code: {patient_code}")
        return redirect("/staff_dashboard")
    
    return render_template("add_patient.html")


@app.route("/patient_detail/<string:patient_code>")
@login_required
def patient_detail(patient_code):
    if session.get("role") not in ["staff", "admin", "patient"]:
        return apology("access denied", 403)

    patient = db.execute("SELECT * FROM records WHERE patient_code = ?", patient_code)

    if not patient:
        return apology("Patient record not found", 404)

    # if patient, make sure they're only accessing their own record
    if session["role"] == "patient" and patient_code != session.get("patient_code"):
        return apology("access denied", 403)

    return render_template("patient_detail.html", patient=patient[0])




@app.route("/search_patient")
@login_required
def search_patient():
    if session.get("role") not in ["staff", "admin"]:
        return apology("access denied", 403)
    
    query = request.args.get("q")
    patients = []
    if query:
        patients = db.execute("""
            SELECT * FROM records
            WHERE patient_name LIKE ? OR room_number LIKE ?
        """, f"%{query}%", f"%{query}%")
    
    return render_template("search_patient.html", patients=patients)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username").lower().strip()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Must Provide Username")
        if not password:
            return apology("Must Provide Password")
        if not confirmation:
            return apology("Must Provide Confirmation")
        if password != confirmation:
            return apology("Passwords Don't Match!")

        hash = generate_password_hash(password)
        user_uuid = str(uuid.uuid4())[:8]  # ✅ Generate unique short UUID for patient

        try:
            new_user = db.execute(
                "INSERT INTO users (username, hash, role, uuid) VALUES (?, ?, ?, ?)",
                username, hash, "patient", user_uuid
            )
        except:
            return apology("This Username already exists. Please try another one")

        # Store session info
        session["user_id"] = new_user
        session["role"] = "patient"
        session["patient_code"] = None  # will be assigned later by staff when adding medical records

        flash(f"✅ Patient registered successfully! UUID: {user_uuid}")
        return redirect("/patient_dashboard")


# @app.route("/register", methods=["GET", "POST"])
# def register():
#     if request.method == "GET":
#         return render_template("register.html")
#     else:
#         username = request.form.get("username").lower().strip()
#         password = request.form.get("password")
#         confirmation = request.form.get("confirmation")

#         if not username:
#             return apology("Must Provide Username")
#         if not password:
#             return apology("Must Provide Password")
#         if not confirmation:
#             return apology("Must Provide Confirmation")
#         if password != confirmation:
#             return apology("Passwords Don't Match!")

#         hash = generate_password_hash(password)

#         try:
#             new_user = db.execute(
#                 "INSERT INTO users (username, hash, role) VALUES(?, ?, ?)",
#                 username, hash, "patient"
#             )
#         except:
#             return apology("This Username already exists. Please try another one")

#         # Try to find existing patient_code for this user
#         patient_record = db.execute("SELECT patient_code FROM records WHERE patient_name = ?", username)

#         if patient_record:
#             session["patient_code"] = patient_record[0]["patient_code"]
#         else:
#             session["patient_code"] = None  # will need staff to assign

#         session["user_id"] = new_user
#         session["role"] = "patient"

#         return redirect("/patient_dashboard")


@app.route("/register_staff", methods=["GET", "POST"])
@login_required
def register_staff():
    if session.get("role") != "admin":
        return apology("access denied", 403)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hash = generate_password_hash(password)
        staff_uuid = str(uuid.uuid4())[:8]  # short unique ID
        try:
             db.execute(
                "INSERT INTO users (username, hash, role, uuid) VALUES (?, ?, ?, ?)",
                username, hash, "staff", staff_uuid
            )
        except:
            return apology("Username already exists")
        flash(f"Staff account created! UUID: {staff_uuid}")
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
        return apology("access denied", 403)

    patients = db.execute("SELECT id, username, role, uuid FROM users WHERE role = 'patient'")
    return render_template("manage_patients.html", patients=patients)


@app.route("/manage_staff")
@login_required
def manage_staff():
    if session.get("role") != "admin":
        return apology("access denied", 403)

    staff = db.execute("SELECT id, username, role, uuid FROM users WHERE role = 'staff'")
    return render_template("manage_staff.html", staff=staff)


@app.route("/confirm_delete_user/<int:user_id>")
@login_required
def confirm_delete_user(user_id):
    if session.get("role") != "admin":
        return apology("access denied", 403)

    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return apology("User not found", 404)

    return render_template("confirm_delete_user.html", user=user[0])


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if session.get("role") != "admin":
        return apology("access denied", 403)

    confirm_uuid = request.form.get("confirm_uuid")
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)

    if not user:
        return apology("User not found", 404)

    if confirm_uuid != user[0]["uuid"]:
        flash("❌ UUID mismatch. Deletion cancelled.")
        return redirect(f"/confirm_delete_user/{user_id}")

    db.execute("DELETE FROM users WHERE id = ?", user_id)
    flash(f"✅ User account '{user[0]['username']}' deleted successfully.")
    return redirect("/admin_dashboard")


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


@app.route("/generate_health_card", methods=["POST"])
def generate_health_card():
    data = request.json
    patient_id = data.get("patient_id")

    if not patient_id:
        return {"error": "Missing patient_id"}, 400

    patient = db.execute("SELECT * FROM records WHERE id = ?", patient_id)

    if not patient:
        return {"error": "Patient not found"}, 404

    return {
        "patient_name": patient[0]["patient_name"],
        "blood_group": patient[0]["blood_group"],
        "weight": patient[0]["weight"],
        "height": patient[0]["height"],
        "doctor_name": patient[0]["doctor_name"],
        "insurance_company": patient[0]["insurance_company"],
        "issued_at": datetime.now().isoformat()
    }
