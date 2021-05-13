from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from WebApp.models import User

itemSortOptions = [
    ('oldDate', 'Oldest Date'),
    ('newDate', 'Newest Date'),
    ('userName', 'Username')
]


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=15)])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    inviteKey = PasswordField("Invite Key", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')


class LogInForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember My Login")
    submit = SubmitField("Login")


class ItemForm(FlaskForm):
    text = StringField("Text", validators=[Length(min=3, max=200)])
    submitAdd = SubmitField("Add item")
    submitDel = SubmitField("Remove Checked Items")
    box = BooleanField("Remove")


class SortDropDown(FlaskForm):
    sortOptions = SelectField("Sort items", choices=itemSortOptions)
    applyButton = SubmitField("Sort items")


class ChangePassword(FlaskForm):
    password = PasswordField("Current Password", validators=[DataRequired()])
    newPassword = PasswordField("New Password", validators=[DataRequired()])
    confirmNewPassword = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("newPassword")])
    submit = SubmitField("Submit")


class ChangeUsername(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=15)])
    password = PasswordField("Current Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class DeleteAccount(FlaskForm):
    password = PasswordField("Current Password", validators=[DataRequired()])
    submit = SubmitField("Delete Account")


class MakeAdminFrom(FlaskForm):
    sortOptions = SelectField("Users", choices=itemSortOptions)
    applyButton = SubmitField("Toggle Admin")


class InviteKey(FlaskForm):
    key = StringField("Invite Key", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")
