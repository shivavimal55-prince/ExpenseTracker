import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
import psycopg2
import psycopg2.extras

app = Flask(__name__)

# =====================================================
# SESSION SECURITY
# =====================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "expense_tracker_secret_key_2026"
)
# =====================================================
# DATABASE CONNECTION
# =====================================================

def get_db_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


# =====================================================
# DATABASE SETUP
# =====================================================

def setup_database():
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Add user_id to expenses table
        cur.execute("""
            ALTER TABLE expenses
            ADD COLUMN IF NOT EXISTS user_id INTEGER
        """)

        # Add user_id to income table
        cur.execute("""
            ALTER TABLE income
            ADD COLUMN IF NOT EXISTS user_id INTEGER
        """)

        # Create budgets table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS budgets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                month VARCHAR(7) NOT NULL,
                amount NUMERIC(12, 2) NOT NULL,
                UNIQUE(user_id, month)
            )
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()

# =====================================================
# AMOUNT VALIDATION
# =====================================================

def get_valid_amount(value):
    try:
        amount = float(value)

        if amount <= 0:
            return None

        if amount > 100000000:
            return None

        return amount

    except (ValueError, TypeError):
        return None


# =====================================================
# SIGNUP
# =====================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return redirect("/signup")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect("/signup")

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        try:

            cur.execute("""
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
            """, (
                name,
                email,
                password_hash
            ))

            conn.commit()

            flash(
                "Account created successfully. Please login.",
                "success"
            )

            return redirect("/login")

        except psycopg2.errors.UniqueViolation:

            conn.rollback()

            flash(
                "Email already registered. Please use another email.",
                "error"
            )

            return redirect("/signup")

        except Exception:

            conn.rollback()

            flash(
                "Something went wrong while creating your account.",
                "error"
            )

            return redirect("/signup")

        finally:

            cur.close()
            conn.close()

    return render_template("signup.html")


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect("/login")

        conn = get_db_connection()
        cur = conn.cursor()

        try:

            cur.execute("""
                SELECT id, name, email, password
                FROM users
                WHERE email = %s
            """, (email,))

            user = cur.fetchone()

        finally:

            cur.close()
            conn.close()

        if user and check_password_hash(user[3], password):

            session.clear()

            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["user_email"] = user[2]

            return redirect("/")

        flash("Invalid email or password.", "error")
        return redirect("/login")

    return render_template("login.html")


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect("/login")


# =====================================================
# SETTINGS
# =====================================================

@app.route("/settings")
def settings():

    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "settings.html",
        user_name=session.get("user_name"),
        user_email=session.get("user_email")
    )


# =====================================================
# UPDATE PROFILE
# =====================================================

@app.route("/update-profile", methods=["POST"])
def update_profile():

    if "user_id" not in session:
        return redirect("/login")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect("/settings")

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        # Check duplicate email
        cur.execute("""
            SELECT id
            FROM users
            WHERE email = %s
            AND id != %s
        """, (
            email,
            session["user_id"]
        ))

        existing_user = cur.fetchone()

        if existing_user:

            flash(
                "This email is already registered.",
                "error"
            )

            return redirect("/settings")

        # Update profile
        cur.execute("""
            UPDATE users
            SET
                name = %s,
                email = %s
            WHERE id = %s
        """, (
            name,
            email,
            session["user_id"]
        ))

        conn.commit()

        # Update session
        session["user_name"] = name
        session["user_email"] = email

        flash(
            "Profile updated successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while updating profile.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/settings")


# =====================================================
# CHANGE PASSWORD
# =====================================================

@app.route("/change-password", methods=["POST"])
def change_password():

    if "user_id" not in session:
        return redirect("/login")

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if not current_password or not new_password or not confirm_password:

        flash(
            "All password fields are required.",
            "error"
        )

        return redirect("/settings")

    if len(new_password) < 6:

        flash(
            "New password must be at least 6 characters.",
            "error"
        )

        return redirect("/settings")

    if new_password != confirm_password:

        flash(
            "New passwords do not match.",
            "error"
        )

        return redirect("/settings")

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            SELECT password
            FROM users
            WHERE id = %s
        """, (session["user_id"],))

        user = cur.fetchone()

        if not user:

            flash(
                "User not found.",
                "error"
            )

            return redirect("/settings")

        stored_password = user[0]

        # Verify old password
        if not check_password_hash(
            stored_password,
            current_password
        ):

            flash(
                "Current password is incorrect.",
                "error"
            )

            return redirect("/settings")

        # Hash new password
        new_password_hash = generate_password_hash(
            new_password
        )

        # Update password
        cur.execute("""
            UPDATE users
            SET password = %s
            WHERE id = %s
        """, (
            new_password_hash,
            session["user_id"]
        ))

        conn.commit()

        flash(
            "Password changed successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while changing password.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/settings")


# =====================================================
# DELETE ACCOUNT
# =====================================================

@app.route("/delete-account", methods=["POST"])
def delete_account():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    password = request.form.get("password", "")

    if not password:

        flash(
            "Password is required to delete your account.",
            "error"
        )

        return redirect("/settings")

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        # Get password
        cur.execute("""
            SELECT password
            FROM users
            WHERE id = %s
        """, (user_id,))

        user = cur.fetchone()

        if not user:

            session.clear()

            return redirect("/login")

        stored_password = user[0]

        # Verify password
        if not check_password_hash(
            stored_password,
            password
        ):

            flash(
                "Incorrect password. Account was not deleted.",
                "error"
            )

            return redirect("/settings")

        # Delete expenses
        cur.execute("""
            DELETE FROM expenses
            WHERE user_id = %s
        """, (user_id,))

        # Delete income
        cur.execute("""
            DELETE FROM income
            WHERE user_id = %s
        """, (user_id,))

        # Delete budgets
        cur.execute("""
            DELETE FROM budgets
            WHERE user_id = %s
        """, (user_id,))

        # Delete user
        cur.execute("""
            DELETE FROM users
            WHERE id = %s
        """, (user_id,))

        conn.commit()

        session.clear()

        flash(
            "Your account has been deleted successfully.",
            "success"
        )

        return redirect("/login")

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while deleting your account.",
            "error"
        )

        return redirect("/settings")

    finally:

        cur.close()
        conn.close()


# =====================================================
# HOME / DASHBOARD
# =====================================================

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        # ================= EXPENSES =================

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                category,
                expense_date
            FROM expenses
            WHERE user_id = %s
            ORDER BY expense_date DESC, id DESC
        """, (user_id,))

        expense_rows = cur.fetchall()

        # ================= INCOME =================

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                income_date
            FROM income
            WHERE user_id = %s
            ORDER BY income_date DESC, id DESC
        """, (user_id,))

        income_rows = cur.fetchall()

        # ================= CONVERT EXPENSES =================

        expenses = []

        for row in expense_rows:

            expenses.append({
                "id": row[0],
                "title": row[1],
                "amount": float(row[2]),
                "category": row[3],
                "date": str(row[4])
            })

        # ================= CONVERT INCOME =================

        incomes = []

        for row in income_rows:

            incomes.append({
                "id": row[0],
                "title": row[1],
                "amount": float(row[2]),
                "date": str(row[3])
            })

        # ================= TOTALS =================

        total_income = sum(
            income["amount"]
            for income in incomes
        )

        total_expense = sum(
            expense["amount"]
            for expense in expenses
        )

        balance = total_income - total_expense

        # ================= PERCENTAGES =================

        if total_income > 0:

            savings_percentage = (
                balance / total_income
            ) * 100

            expense_percentage = (
                total_expense / total_income
            ) * 100

        else:

            savings_percentage = 0
            expense_percentage = 0

        # ================= CURRENT MONTH =================

        current_month = date.today().strftime("%Y-%m")

        # ================= BUDGET =================

        cur.execute("""
            SELECT amount
            FROM budgets
            WHERE user_id = %s
            AND month = %s
        """, (
            user_id,
            current_month
        ))

        budget_row = cur.fetchone()

        if budget_row:
            monthly_budget = float(budget_row[0])
        else:
            monthly_budget = 0

        # ================= CURRENT MONTH EXPENSE =================

        cur.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM expenses
            WHERE user_id = %s
            AND TO_CHAR(expense_date, 'YYYY-MM') = %s
        """, (
            user_id,
            current_month
        ))

        current_month_expense = float(
            cur.fetchone()[0]
        )

        # ================= BUDGET REMAINING =================

        budget_remaining = (
            monthly_budget -
            current_month_expense
        )

        # ================= BUDGET PERCENTAGE =================

        if monthly_budget > 0:

            budget_used_percentage = (
                current_month_expense /
                monthly_budget
            ) * 100

        else:

            budget_used_percentage = 0

        budget_progress_percentage = min(
            budget_used_percentage,
            100
        )

        # ================= TRANSACTIONS =================

        total_transactions = (
            len(expenses) +
            len(incomes)
        )

        # ================= CATEGORY TOTALS =================

        category_totals = {}

        for expense in expenses:

            category = expense["category"]
            amount = expense["amount"]

            if category in category_totals:

                category_totals[category] += amount

            else:

                category_totals[category] = amount

        # ================= TOP CATEGORY =================

        if category_totals:

            top_category = max(
                category_totals,
                key=category_totals.get
            )

        else:

            top_category = "No data"

        # ================= HIGHEST EXPENSE =================

        if expenses:

            highest_expense = max(
                expenses,
                key=lambda x: x["amount"]
            )

            highest_expense_title = (
                highest_expense["title"]
            )

            highest_expense_amount = (
                highest_expense["amount"]
            )

        else:

            highest_expense_title = "No data"
            highest_expense_amount = 0

        # ================= MONTHLY EXPENSE =================

        monthly_totals = {}

        for expense in expenses:

            month = expense["date"][:7]
            amount = expense["amount"]

            if month in monthly_totals:

                monthly_totals[month] += amount

            else:

                monthly_totals[month] = amount

        # ================= MONTHLY INCOME =================

        monthly_income = {}

        for income in incomes:

            month = income["date"][:7]
            amount = income["amount"]

            if month in monthly_income:

                monthly_income[month] += amount

            else:

                monthly_income[month] = amount

        # ================= MONTHLY COMPARISON =================

        all_months = (
            set(monthly_totals.keys())
            |
            set(monthly_income.keys())
        )

        monthly_comparison = {}

        for month in sorted(all_months):

            monthly_comparison[month] = {
                "income": monthly_income.get(
                    month,
                    0
                ),
                "expense": monthly_totals.get(
                    month,
                    0
                )
            }

    finally:

        cur.close()
        conn.close()

    # ================= RENDER =================

    return render_template(
        "index.html",

        expenses=expenses,
        incomes=incomes,

        total_expense=total_expense,
        total_income=total_income,
        balance=balance,

        current_month=current_month,

        monthly_budget=monthly_budget,
        current_month_expense=current_month_expense,
        budget_remaining=budget_remaining,

        budget_used_percentage=budget_used_percentage,
        budget_progress_percentage=budget_progress_percentage,

        savings_percentage=savings_percentage,
        expense_percentage=expense_percentage,

        category_totals=category_totals,

        monthly_totals=monthly_totals,
        monthly_income=monthly_income,
        monthly_comparison=monthly_comparison,

        total_transactions=total_transactions,

        top_category=top_category,

        highest_expense_title=highest_expense_title,
        highest_expense_amount=highest_expense_amount,

        user_name=session.get("user_name")
    )


# =====================================================
# ADD EXPENSE
# =====================================================

@app.route("/add", methods=["POST"])
def add_expense():

    if "user_id" not in session:
        return redirect("/login")

    title = request.form.get(
        "title",
        ""
    ).strip()

    amount = get_valid_amount(
        request.form.get("amount")
    )

    category = request.form.get(
        "category",
        ""
    ).strip()

    expense_date = request.form.get(
        "date",
        ""
    )

    if not title or not category or not expense_date:

        flash(
            "Please fill all expense fields.",
            "error"
        )

        return redirect("/")

    if amount is None:

        flash(
            "Invalid amount. Please enter a positive amount.",
            "error"
        )

        return redirect("/")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            INSERT INTO expenses (
                title,
                amount,
                category,
                expense_date,
                user_id
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            title,
            amount,
            category,
            expense_date,
            user_id
        ))

        conn.commit()

        flash(
            "Expense added successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while adding expense.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/")


# =====================================================
# DELETE EXPENSE
# =====================================================

@app.route("/delete/<int:id>")
def delete_expense(id):

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            DELETE FROM expenses
            WHERE id = %s
            AND user_id = %s
        """, (
            id,
            user_id
        ))

        conn.commit()

        flash(
            "Expense deleted successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while deleting expense.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/")


# =====================================================
# EXPENSES PAGE
# =====================================================

@app.route("/expenses")
def expenses_page():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                category,
                expense_date
            FROM expenses
            WHERE user_id = %s
            ORDER BY expense_date DESC, id DESC
        """, (user_id,))

        rows = cur.fetchall()

    finally:

        cur.close()
        conn.close()

    expenses = []

    for row in rows:

        expenses.append({
            "id": row[0],
            "title": row[1],
            "amount": float(row[2]),
            "category": row[3],
            "date": str(row[4])
        })

    total_expense = sum(
        expense["amount"]
        for expense in expenses
    )

    return render_template(
        "expenses.html",
        expenses=expenses,
        total_expense=total_expense,
        user_name=session.get("user_name")
    )


# =====================================================
# EDIT EXPENSE
# =====================================================

@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_expense(id):

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ================= UPDATE =================

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        amount = get_valid_amount(
            request.form.get("amount")
        )

        category = request.form.get(
            "category",
            ""
        ).strip()

        expense_date = request.form.get(
            "date",
            ""
        )

        if not title or not category or not expense_date:

            cur.close()
            conn.close()

            flash(
                "Please fill all fields.",
                "error"
            )

            return redirect(f"/edit/{id}")

        if amount is None:

            cur.close()
            conn.close()

            flash(
                "Invalid amount. Please enter a positive amount.",
                "error"
            )

            return redirect(f"/edit/{id}")

        try:

            cur.execute("""
                UPDATE expenses
                SET
                    title = %s,
                    amount = %s,
                    category = %s,
                    expense_date = %s
                WHERE id = %s
                AND user_id = %s
            """, (
                title,
                amount,
                category,
                expense_date,
                id,
                user_id
            ))

            if cur.rowcount == 0:

                conn.rollback()

                flash(
                    "Expense record not found.",
                    "error"
                )

                return redirect("/expenses")

            conn.commit()

            flash(
                "Expense updated successfully.",
                "success"
            )

            return redirect("/expenses")

        except Exception:

            conn.rollback()

            flash(
                "Something went wrong while updating expense.",
                "error"
            )

            return redirect(f"/edit/{id}")

        finally:

            cur.close()
            conn.close()

    # ================= GET =================

    try:

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                category,
                expense_date
            FROM expenses
            WHERE id = %s
            AND user_id = %s
        """, (
            id,
            user_id
        ))

        expense = cur.fetchone()

    finally:

        cur.close()
        conn.close()

    if not expense:

        flash(
            "Expense record not found.",
            "error"
        )

        return redirect("/expenses")

    return render_template(
        "edit.html",
        expense=expense
    )


# =====================================================
# ADD INCOME
# =====================================================

@app.route("/add-income", methods=["POST"])
def add_income():

    # Login check
    if "user_id" not in session:
        return redirect("/login")

    # Get form data
    title = request.form.get("title", "").strip()
    amount = get_valid_amount(request.form.get("amount"))
    income_date = request.form.get("date", "")

    # Validate fields
    if not title or not income_date:
        flash("Please fill all income fields.", "error")
        return redirect("/income")

    if amount is None:
        flash(
            "Invalid amount. Please enter a positive amount.",
            "error"
        )
        return redirect("/income")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO income (
                title,
                amount,
                income_date,
                user_id
            )
            VALUES (%s, %s, %s, %s)
        """, (
            title,
            amount,
            income_date,
            user_id
        ))

        conn.commit()

        flash(
            "Income added successfully.",
            "success"
        )

    except Exception:
        conn.rollback()

        flash(
            "Something went wrong while adding income.",
            "error"
        )

    finally:
        cur.close()
        conn.close()

    return redirect("/income")
# =====================================================
# DELETE INCOME
# =====================================================

@app.route("/delete-income/<int:id>")
def delete_income(id):

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            DELETE FROM income
            WHERE id = %s
            AND user_id = %s
        """, (
            id,
            user_id
        ))

        conn.commit()

        flash(
            "Income deleted successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while deleting income.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/")


# =====================================================
# INCOME PAGE
# =====================================================

@app.route("/income")
def income_page():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                income_date
            FROM income
            WHERE user_id = %s
            ORDER BY income_date DESC, id DESC
        """, (user_id,))

        rows = cur.fetchall()

    finally:

        cur.close()
        conn.close()

    incomes = []

    for row in rows:

        incomes.append({
            "id": row[0],
            "title": row[1],
            "amount": float(row[2]),
            "date": str(row[3])
        })

    total_income = sum(
        income["amount"]
        for income in incomes
    )

    return render_template(
        "income.html",
        incomes=incomes,
        total_income=total_income,
        user_name=session.get("user_name")
    )


# =====================================================
# EDIT INCOME
# =====================================================


@app.route("/edit-income/<int:id>", methods=["GET", "POST"])
def edit_income(id):

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    # ================= UPDATE =================

    if request.method == "POST":

        title = request.form.get("title", "").strip()

        amount = get_valid_amount(
            request.form.get("amount")
        )

        income_date = request.form.get("date", "")

        if not title or not income_date:
            cur.close()
            conn.close()

            flash(
                "Please fill all fields.",
                "error"
            )

            return redirect(f"/edit-income/{id}")

        if amount is None:
            cur.close()
            conn.close()

            flash(
                "Invalid amount. Please enter a positive amount.",
                "error"
            )

            return redirect(f"/edit-income/{id}")

        try:

            cur.execute("""
                UPDATE income
                SET
                    title = %s,
                    amount = %s,
                    income_date = %s
                WHERE id = %s
                AND user_id = %s
            """, (
                title,
                amount,
                income_date,
                id,
                user_id
            ))

            if cur.rowcount == 0:

                conn.rollback()

                flash(
                    "Income record not found.",
                    "error"
                )

                return redirect("/income")

            conn.commit()

            flash(
                "Income updated successfully.",
                "success"
            )

            return redirect("/income")

        except Exception as e:

            conn.rollback()

            print("EDIT INCOME ERROR:", e)

            flash(
                "Something went wrong while updating income.",
                "error"
            )

            return redirect(f"/edit-income/{id}")

        finally:
            cur.close()
            conn.close()

    # ================= GET =================

    try:

        cur.execute("""
            SELECT
                id,
                title,
                amount,
                income_date
            FROM income
            WHERE id = %s
            AND user_id = %s
        """, (
            id,
            user_id
        ))

        row = cur.fetchone()

    finally:

        cur.close()
        conn.close()

    if not row:

        flash(
            "Income record not found.",
            "error"
        )

        return redirect("/income")

    # Convert tuple into dictionary
    income = {
        "id": row[0],
        "title": row[1],
        "amount": float(row[2]),
        "date": str(row[3])
    }

    return render_template(
        "edit_income.html",
        income=income
    )


# =====================================================
# SET MONTHLY BUDGET
# =====================================================

@app.route("/set-budget", methods=["POST"])
def set_budget():
    if "user_id" not in session:
        return redirect(url_for("login"))

    budget = request.form.get("budget")

    try:
        budget = float(budget)

        if budget <= 0 or budget > 100000000:
            return redirect(url_for("home"))

    except (ValueError, TypeError):
        return redirect(url_for("home"))

    # Current month in YYYY-MM format
    current_month = datetime.now().strftime("%Y-%m")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO budgets (user_id, month, amount)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id, month)
        DO UPDATE SET amount = EXCLUDED.amount
    """, (session["user_id"], current_month, budget))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("home"))

    # ================= VALIDATE MONTH =================

    try:

        budget_month = date.fromisoformat(
            month + "-01"
        )

        month = budget_month.strftime("%Y-%m")

    except ValueError:

        flash(
            "Invalid budget month.",
            "error"
        )

        return redirect("/")

    # ================= VALIDATE AMOUNT =================

    amount = get_valid_amount(
        request.form.get("amount")
    )

    if amount is None:

        flash(
            "Invalid budget amount.",
            "error"
        )

        return redirect("/")

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        cur.execute("""
            INSERT INTO budgets (
                user_id,
                month,
                amount
            )
            VALUES (%s, %s, %s)

            ON CONFLICT (user_id, month)

            DO UPDATE SET
                amount = EXCLUDED.amount
        """, (
            user_id,
            month,
            amount
        ))

        conn.commit()

        flash(
            "Monthly budget saved successfully.",
            "success"
        )

    except Exception:

        conn.rollback()

        flash(
            "Something went wrong while saving budget.",
            "error"
        )

    finally:

        cur.close()
        conn.close()

    return redirect("/")


# =====================================================
# ANALYTICS
# =====================================================

@app.route("/analytics")
def analytics():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        # ================= CATEGORY EXPENSE =================

        cur.execute("""
            SELECT
                category,
                COALESCE(SUM(amount), 0)
            FROM expenses
            WHERE user_id = %s
            GROUP BY category
            ORDER BY SUM(amount) DESC
        """, (user_id,))

        category_rows = cur.fetchall()

        category_labels = []
        category_values = []

        for row in category_rows:

            category_labels.append(row[0])
            category_values.append(float(row[1]))

        # ================= MONTHLY EXPENSE =================

        cur.execute("""
            SELECT
                TO_CHAR(expense_date, 'YYYY-MM'),
                COALESCE(SUM(amount), 0)
            FROM expenses
            WHERE user_id = %s
            GROUP BY TO_CHAR(expense_date, 'YYYY-MM')
            ORDER BY TO_CHAR(expense_date, 'YYYY-MM')
        """, (user_id,))

        expense_rows = cur.fetchall()

        # ================= MONTHLY INCOME =================

        cur.execute("""
            SELECT
                TO_CHAR(income_date, 'YYYY-MM'),
                COALESCE(SUM(amount), 0)
            FROM income
            WHERE user_id = %s
            GROUP BY TO_CHAR(income_date, 'YYYY-MM')
            ORDER BY TO_CHAR(income_date, 'YYYY-MM')
        """, (user_id,))

        income_rows = cur.fetchall()

    finally:

        cur.close()
        conn.close()

    # ================= MONTHLY DATA =================

    monthly_expense = {}

    for row in expense_rows:

        monthly_expense[row[0]] = float(row[1])

    monthly_income = {}

    for row in income_rows:

        monthly_income[row[0]] = float(row[1])

    all_months = sorted(
        set(monthly_expense.keys())
        |
        set(monthly_income.keys())
    )

    expense_values = [
        monthly_expense.get(
            month,
            0
        )
        for month in all_months
    ]

    income_values = [
        monthly_income.get(
            month,
            0
        )
        for month in all_months
    ]

    # ================= TOTALS =================

    total_income = sum(income_values)

    total_expense = sum(expense_values)

    balance = (
        total_income -
        total_expense
    )

    # ================= SAVINGS =================

    if total_income > 0:

        savings_percentage = (
            balance /
            total_income
        ) * 100

    else:

        savings_percentage = 0

    # ================= RENDER =================

    return render_template(
        "analytics.html",

        category_labels=category_labels,
        category_values=category_values,

        months=all_months,

        expense_values=expense_values,
        income_values=income_values,

        total_income=total_income,
        total_expense=total_expense,
        balance=balance,

        savings_percentage=savings_percentage,

        user_name=session.get("user_name")
    )


# =====================================================
# START APPLICATION
# =====================================================

if __name__ == "__main__":

    setup_database()

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )

