# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, TextAreaField, SubmitField,PasswordField,BooleanField,RadioField,HiddenField,SelectField,FloatField,IntegerField,DecimalField
from wtforms.validators import DataRequired,Email,Length,Optional,EqualTo,NumberRange,URL

class EditUserForm(FlaskForm):
    user_id = HiddenField("User ID")
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')],
                         validators=[Optional()])
    submit = SubmitField('Update User')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password',
                                  validators=[DataRequired(),
                                              Length(min=8, max=20, message='Password must be between 8 to 20 characters.')])
    confirm_password = PasswordField('Confirm Password',
                                      validators=[DataRequired(),
                                                  EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')
class OTPForm(FlaskForm):
    otp = StringField('Enter the OTP sent to your email (valid for 2 minutes).', validators=[DataRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Enter your OTP here"})
    submit = SubmitField('Submit')
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')
class DeleteUserForm(FlaskForm):
    user_id = HiddenField("User ID")
    submit = SubmitField("Delete User")

class GenderForm(FlaskForm):
    gender = RadioField('Gender', choices=[
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other')
    ])
    submit = SubmitField('Select Gender')

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=50)])
    gender = RadioField('Gender', choices=[
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other')
    ])
    submit = SubmitField('Update Profile')
class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    email = EmailField('Your Email', validators=[DataRequired()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    repeat_password = PasswordField('Repeat Password', validators=[DataRequired()])
    gender = RadioField('Gender', choices=[
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other')
    ])
    submit = SubmitField('Register Account')

class DeleteProductForm(FlaskForm):
    submit = SubmitField('Delete Product')
class ProductEditForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock Quantity', validators=[DataRequired(), NumberRange(min=0)])
    sales = IntegerField('Sales Quantity', validators=[DataRequired(), NumberRange(min=0)])
    rating = FloatField('Rating (1-5)', validators=[Optional(), NumberRange(min=0, max=5)])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    discountPercentage = FloatField('Discount Percentage', validators=[Optional(), NumberRange(min=0, max=100)])
    thumbnail = StringField('Thumbnail URL', validators=[Optional()])
    featured = BooleanField('Featured', validators=[DataRequired()])
    submit = SubmitField('Update Product')


class AddProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Product Description', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock Quantity', validators=[DataRequired()])
    rating = DecimalField('Rating', validators=[Optional()])

    # Additional Fields
    tags = StringField('Tags (Comma Separated)', validators=[Optional()])  # JSON String or list of tags
    brand = StringField('Brand', validators=[Optional()])
    sku = StringField('SKU', validators=[Optional()])
    weight = DecimalField('Weight (in kg)', validators=[Optional()])

    # Dimensions as a JSON object (you can use a text field for JSON input or individual fields)
    dimensions_width = DecimalField('Width', validators=[Optional()])
    dimensions_height = DecimalField('Height', validators=[Optional()])
    dimensions_depth = DecimalField('Depth', validators=[Optional()])

    warranty_information = StringField('Warranty Information', validators=[Optional()])
    shipping_information = StringField('Shipping Information', validators=[Optional()])
    availability_status = StringField('Availability Status', validators=[Optional()])
    return_policy = StringField('Return Policy', validators=[Optional()])
    minimum_order_quantity = IntegerField('Minimum Order Quantity', validators=[Optional()])

    # Metadata
    barcode = StringField('Barcode', validators=[Optional()])
    qr_code = StringField('QR Code URL', validators=[Optional(), URL()])

    # Images
    images = StringField('Image URLs (JSON format)', validators=[Optional()])
    thumbnail = StringField('Thumbnail URL', validators=[Optional(), URL()])

    # Category (You can use a dropdown for categories)
    category_id = SelectField('Category', coerce=int, choices=[], validators=[DataRequired()])

class AddCategoryForm(FlaskForm):
    category_name = StringField('Category Name', validators=[DataRequired()])
    thumbnail = StringField('Thumbnail', validators=[Optional()])

class CategoryForm(FlaskForm):
    category_name = StringField('Category Name', validators=[DataRequired()])
    thumbnail = StringField('Thumbnail', validators=[Optional()])