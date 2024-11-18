# Python module imports
import datetime as dt
import hashlib
from flask import Flask, request, render_template, Response, flash, session, redirect
from flask_session import Session

# Importing local functions
from block import *
from genesis import create_genesis_block
from newBlock import next_block, add_block
from getBlock import find_records
# from checkChain import check_integrity

#New imports
from os import chdir, listdir, remove, getcwd
import re
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import *

# Flask declarations
app = Flask(__name__)
# A nice Secret Key for flash messages
app.config['SECRET_KEY'] = '69'
response = Response()
response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0')

# Initializing blockchain with the genesis block
blockchain = create_genesis_block()
data = []

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Evoid redondemcy by using is_provided function
def is_provided(field):

    if not request.form.get(field):
        return error(f"MUST PROVIDE {field}", 400)


# Main index - Blockchain Validity Status
@app.route('/')
@login_required
def check():
    username0 = db.execute("""
        SELECT username FROM users
        WHERE id=:user_id""", user_id=session["user_id"])
    username = (str(username0)).strip().replace("username","").replace(":","").replace("[{","").replace("'}]","").replace("''","").replace("'","") # Yea, I know... (-_-)
    
    # results = check_integrity()
    return render_template('index.html', username=username)



# Default Landing page of the app
@app.route('/',  methods = ['GET'])
def index():
    return render_template("index.html")

# Get Form input and decide what is to be done with it
@app.route('/', methods = ['POST'])
def parse_request():
    if(request.form.get("name")):
        while len(data) > 0:
            data.pop()
        data.append(request.form.get("name"))
        data.append(str(dt.date.today()))
        return render_template("class.html",
                                name = request.form.get("name"),
                                date = dt.date.today())

    elif(request.form.get("number")):
        while len(data) > 2:
            data.pop()
        data.append(request.form.get("course"))
        data.append(request.form.get("year"))
        return render_template("attendance.html",
                                name = data[0],
                                course = request.form.get("course"),
                                year = request.form.get("year"),
                                number = int(request.form.get("number")))
    elif(request.form.get("roll_no1")):
        while len(data) > 4:
            data.pop()
        return render_template("result.html", result = add_block(request.form, data, blockchain))

    else:
        return "Invalid POST request. This incident has been recorded."



#Log user in
@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username and password was submitted
        result_check = is_provided("username") or is_provided("password")
        if result_check is not None:
            return result_check

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("INVALID USERNAME AND/OR PASSWORD", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Log user out
@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# Password Validation Function
def validate(password):

    if len(password) < 8:
        return error("Password should be at least 8 characters.")
    

# Register a new user
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        # Ensure username password and confirmation was provided
        result_check = is_provided("username") or is_provided("password") or is_provided("confirmation")

        if result_check != None:
            return result_check

        # Validate the user password
        validation_errors = validate(request.form.get("password"))
        if validation_errors:
            return validation_errors

        # Ensure password and confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return error("PASSWORDS DOES NOT MATCH.")

        # Query database for username
        try:
            prim_key = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                                  username=request.form.get("username").lower(),
                                  hash=generate_password_hash(request.form.get("password")))
        except:
            return error("USERNAME ALREADY EXISTS.", 400)

        if prim_key is None:
            return error("REGISTRATION ERROR.", 403)

        # Remember which user has logged in
        session["user_id"] = prim_key

        flash("Registered!")
        return redirect("/")

    else:
        return render_template("register.html")


# Handle Error
def errorhandler(e):

    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# Show page to get information for fetching records
@app.route('/view.html',  methods = ['GET'])
def view():
    return render_template("class.html")

# Process form input for fetching records from the blockchain
@app.route('/view.html',  methods = ['POST'])
def show_records():
    data = []
    data = find_records(request.form, blockchain)
    if data == -1:
        return "Records not found"
    return render_template("view.html",
                            name = request.form.get("name"),
                            course = request.form.get("course"),
                            year = request.form.get("year"),
                            status = data,
                            number = int(request.form.get("number")),
                            date = request.form.get("date"))

# Show page with result of checking blockchain integrity
# @app.route('/result.html',  methods = ['GET'])
# def check_new():
#     return render_template("result.html", result = check_integrity(blockchain))

# Start the flask app when program is executed
if __name__ == "__main__":
    app.run(debug=True)
