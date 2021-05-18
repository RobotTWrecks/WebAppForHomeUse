from . import app, db, bcrypt, inviteKeyList, config_file
from .utilities import getEpoch, epochToDate, logUser, removeItem, no_Default_Admin_Password
from .models import User, Items
from .forms import RegistrationForm, LogInForm, ItemForm, SortDropDown, InviteKey, \
    ChangeUsername, ChangePassword, DeleteAccount
from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required

# TODO Add work out tracking
# TODO Add youtube-dl app

# user can make an account
@app.route("/register", methods=['GET', 'POST'])
def register():
    # Check session
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # get form
    form = RegistrationForm()

    # Check if form is 
    if form.validate_on_submit():
        if form.inviteKey.data in inviteKeyList:
            # Remove invite key     
            inviteKeyList.pop(inviteKeyList.index(form.inviteKey.data))

            # Hash password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # Get user info from form
            user = User(username=form.username.data, password=hashed_password, dateAdded=getEpoch(), isAdmin='false')

            try:
                # Add user*
                db.session.add(user)
                db.session.commit()
                flash('Your account has been created! You are now able to log in', 'success')
                # Send them to the login
                return redirect(url_for('login'))
            # TODO be more helpful?
            except Exception as err:
                # Undo if it broke
                db.session.rollback()
                print(err)
                flash('Your account has not been created', 'danger')
        else:
            flash('Invite Key is not in the list. Contact the admin to add one.', 'warning')
    return render_template('register.html',
                           webAppTitle=config_file['WebApp']['title'],
                           title='Register',
                           form=form)


# Log in page
@app.route("/login", methods=['GET', 'POST'])
def login():
    # Check if logged in
    if current_user.is_authenticated:
        return redirect(url_for('listApp'))

    #TODO remove
    #Tell the user how to do a first time login
    #if noDefaultAdminPassword() and request.method != 'POST':
    #    flash('Log in as "admin" and use default password found in config.yml', 'info')'''

    # login get Login Form
    form = LogInForm()

    if form.validate_on_submit():
        # Get User using username
        user = User.query.filter_by(username=form.username.data).first()

        # Check password
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # User login
            login_user(user, remember=form.remember.data)
            # Log the user
            logUser(request, current_user)
            return redirect(url_for('listApp'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html',
                           webAppTitle=config_file['WebApp']['title'],
                           title='Login',
                           form=form)


# Log out the user
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


# index page
@app.route("/index")
@app.route("/", methods=['GET'])
def index():
    # Check user is logged in
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # Give the user the menu
    return render_template('indexMenu.html',
                           webAppTitle=config_file['WebApp']['title'])


# list app page
@app.route("/listApp", methods=['GET', 'POST'])
@login_required
@no_Default_Admin_Password
def listApp():
    # Forms
    sortForm = SortDropDown()
    itemForm = ItemForm()
    # Check how the user wants to sort
    if sortForm.sortOptions.data == "newDate":
        itemsWithUsernames = db.session.execute('select * from itemsPage order by dateAdded DESC')
    elif sortForm.sortOptions.data == "userName":
        itemsWithUsernames = db.session.execute('select * from itemsPage order by username')
    else:
        itemsWithUsernames = db.session.execute('select * from itemsPage order by dateAdded ASC')
    return render_template('listApp.html',
                           webAppTitle=config_file['WebApp']['title'],
                           title='List',
                           itemForm=itemForm,
                           sortForm=sortForm,
                           dateConversion=epochToDate,
                           posts=itemsWithUsernames)


# Used for added an Item
@app.route("/itemAction", methods=['POST'])
@login_required
def itemAction():
    # Get form
    addItemForm = ItemForm()
    # Check which button is pressed
    # Add an item button
    if 'submitAdd' in request.form:
        if addItemForm.validate_on_submit():
            anItem = Items(addedByUid=current_user.uid, item=addItemForm.text.data, dateAdded=getEpoch())
            db.session.add(anItem)
            db.session.commit()
        else:
            flash('Posted item needs to be 3-200 characters', 'warning')

    # Remove an item button
    elif 'submitDel' in request.form:
        # remove all items checked
        for formiid in request.form.getlist('box'):
            try:
                formiid = int(formiid)
                removeItem(formiid, current_user.uid)
            except ValueError as err:
                print("[!!] Cause:", formiid, "Error:", err)

    return redirect(url_for('listApp'))


# Page that will show all the past items
@app.route("/removedItems", methods=['POST', 'GET'])
@login_required
def removedItems():
    # Get all removed items
    removedItemsWithUsernames = db.session.execute('select * from removedItemsPage')
    # Show then to the user
    return render_template('removed.html',
                           webAppTitle=config_file['WebApp']['title'],
                           removedItemsList=removedItemsWithUsernames,
                           dateConversion=epochToDate)


# Get account settings and log
@app.route("/loginLog", methods=['POST', 'GET'])
@login_required
def loginLog():
    # Get from
    sortForm = SortDropDown()
    if current_user.isAdmin == 'true':
        # Check if we need to sort
        if sortForm.sortOptions.data == "oldDate":
            sessions = db.session.execute('select * from sessionLog order by issueddate ASC')
        elif sortForm.sortOptions.data == "userName":
            sessions = db.session.execute('select * from sessionLog order by uid')
        else:
            sessions = db.session.execute('select * from sessionLog order by issueddate DESC')
    else:
        sessions = db.session.execute('select * from sessionLog where uid = :uid order by issueddate ASC',
                                      {'uid': current_user.uid}
                                      )
    return render_template('loginLog.html',
                           webAppTitle=config_file['WebApp']['title'],
                           sessions=sessions,
                           sortForm=sortForm,
                           epochToDate=epochToDate)


# Menu for settings
@app.route("/settings", methods=['POST', 'GET'])
@login_required
@no_Default_Admin_Password
def settings():
    # Show page to the user
    return render_template('settings.html',
                           webAppTitle=config_file['WebApp']['title'])


# Page for username update
@app.route("/usernameChange", methods=['POST', 'GET'])
@login_required
@no_Default_Admin_Password
def changeUserName():
    form = ChangeUsername()
    if form.validate_on_submit() and form.username.data != current_user.username:
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            if current_user.username == 'admin':
                flash('Admin account cannot change username.', 'warning')
            else:
                # Update username
                if form.username.data != "":
                    current_user.username = form.username.data
                    db.session.commit()
                    # Tell user
                    flash('Username Updated.', 'success')
                    return redirect(url_for('settings'))
                else:
                    flash('Username cannot be empty.', 'warning')
        else:
            flash('Password does not match.', 'danger')
    # Show page to the user
    return render_template('changeUsername.html',
                           webAppTitle=config_file['WebApp']['title'],
                           form=form)


# Page for password update
@app.route("/passwordChange", methods=['POST', 'GET'])
@login_required
def changePassword():
    form = ChangePassword()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            if form.newPassword.data == form.confirmNewPassword.data:
                current_user.password = bcrypt.generate_password_hash(form.newPassword.data).decode('utf-8')
                db.session.commit()
                flash('Password Updated.', 'success')
                return redirect(url_for('settings'))
            else:
                flash('"New Password" and "Confirm New Password" fields do not match.', 'warning')
        else:
            flash('Password does not match.', 'danger')
    # Show page to the user
    return render_template('changePassword.html',
                           webAppTitle=config_file['WebApp']['title'],
                           form=form)


# Page for Removing account
@app.route("/deleteAccount", methods=['POST', 'GET'])
@login_required
def deleteAccount():
    form = DeleteAccount()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            if current_user.username == 'admin':
                flash('Admin account cannot be deleted.', 'warning')
            else:
                # Delete the user
                # db.session.delete(current_user)
                db.session.execute('Delete from user where uid=:uid', {'uid': current_user.uid})
                db.session.commit()
                # Tell user
                flash('Account Deleted.', 'success')
                # Log out user
                logout_user()
                return redirect(url_for('login'))
        else:
            flash('Password does not match.', 'danger')
    # Show page to the user
    return render_template('deleteAccount.html',
                           webAppTitle=config_file['WebApp']['title'],
                           form=form)


@app.route("/addInviteKey", methods=['POST', 'GET'])
@login_required
@no_Default_Admin_Password
def addInviteKey():
    form = InviteKey()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            inviteKeyList.append(form.key.data)
            flash('Added Invite Key.', 'success')
        else:
            flash('Password does not match.', 'danger')
    # Show page to the user
    return render_template('addInviteKey.html',
                           webAppTitle=config_file['WebApp']['title'],
                           keys=inviteKeyList,
                           form=form)


# list app page
@app.route("/runningApp", methods=['GET', 'POST'])
@login_required
@no_Default_Admin_Password
def runningApp():
    # Forms
    sortForm = SortDropDown()
    itemForm = ItemForm()
    # Check how the user wants to sort
    if sortForm.sortOptions.data == "newDate":
        itemsWithUsernames = db.session.execute('select * from itemsPage order by dateAdded DESC')
    elif sortForm.sortOptions.data == "userName":
        itemsWithUsernames = db.session.execute('select * from itemsPage order by username')
    else:
        itemsWithUsernames = db.session.execute('select * from itemsPage order by dateAdded ASC')
    return render_template('listApp.html',
                           webAppTitle=config_file['WebApp']['title'],
                           title='List',
                           itemForm=itemForm,
                           sortForm=sortForm,
                           dateConversion=epochToDate,
                           posts=itemsWithUsernames)
