from datetime import datetime
from flask import Flask, render_template, request, redirect, flash, session, url_for, abort
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from matplotlib import use
import matplotlib.pyplot as plt
import seaborn as sns
import os

curr_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///A2Z.sqlite3' #ORM = Connects relational DB to objects in python (flask)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #Should track modifications or not
app.config['SECRET_KEY'] = 'thisismysecretkey'
app.config['PASSWORD_HASH'] = 'sha512'
app.config['UPLOAD_EXTENSIONS'] = ['.pdf'] #allowed file upload extensions
app.config['UPLOAD_PATH'] = os.path.join(curr_dir, 'static', 'pdfs')

db = SQLAlchemy()
db.init_app(app)
app.app_context().push()

use('Agg')

'''
from matplotlib import use: This command imports the use function from the Matplotlib library. Use is a function that allows you to set the backend of Matplotlib. The backend is what Matplotlib uses to render your plots.

use('Agg'): This command sets the backend to Agg. Agg stands for Anti-Grain Geometry, and it is a non-interactive backend that is great for generating images (like PNG files) programmatically. 
By setting the backend to Agg, you ensure that Matplotlib does not attempt to open any interactive windows for your plots, 
which is useful when running in environments where you don't have a display (like in web servers or scripts).

Using these commands, you're configuring Matplotlib to use a backend that suits your need to generate and save plots to files without requiring a display, avoiding the RuntimeError related to GUI operations in non-main threads.
'''

#MODELS
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(120), nullable=True)
    pincode = db.Column(db.Integer, nullable=True)
    role = db.Column(db.String(80), nullable=False) #customer, service_proff, admin
    is_approved = db.Column(db.Boolean, default=False)
    is_rejected = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    avg_rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)
    service_proffessional_file = db.Column(db.String(120), nullable=True)
    service_proffesional_experience = db.Column(db.String(120), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('householdServices.id', ondelete='SET NULL'), nullable=True) #bcoz our relationship with services table is 1 to many and 1 user can exist without a service
    service = db.relationship('HouseholdServices', back_populates='service_proffessionals') #2-way connection service_proffesionals(HouseholdServices Table) and service(User table)
    #One to Many relationship. 1 service will have many service_proffessionals but 1 service_proffessional can only have 1 service.
    
    #Relationship for requests customer made
    customer_requests = db.relationship('HouseholdServiceRequest', back_populates='customer', foreign_keys='HouseholdServiceRequest.customer_id')
    
    #Relationship for requests made to service proffessional
    service_proffessional_requests = db.relationship('HouseholdServiceRequest', back_populates='service_proffessional', foreign_keys='HouseholdServiceRequest.service_proffessional_id')

class HouseholdServices(db.Model):
    __tablename__ = "householdServices"
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(80), unique=True, nullable=False)
    service_description = db.Column(db.String(120), nullable=True)
    base_price = db.Column(db.Integer, nullable=True)
    time_required = db.Column(db.String(80), nullable=True)
    service_proffessionals = db.relationship('User', back_populates='service', cascade = 'all, delete') #2-way connection to user.service + if we delete-orphan, then all contractors related to deleted service will get deleted, 
    #but we want only the particular sevice_proff to get deleted
    request = db.relationship('HouseholdServiceRequest', back_populates='service', cascade = 'all, delete-orphan') #If any service is deleted, delete all the service requests associated with it.

class HouseholdServiceRequest(db.Model):
    __tablename__ = 'householdServiceRequest'
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('householdServices.id'), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_proffessional_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    #req_type = db.Column(db.String(10), nullable=False) #private / public
    description = db.Column(db.Text, nullable=True) #request description
    status = db.Column(db.String(80), nullable=True) #pending / accepted / closed / rejected
    date_created = db.Column(db.Date, nullable=False, default=datetime.now().date())
    date_closed = db.Column(db.Date, nullable=True)
    rating_by_customer = db.Column(db.Float, default=0.0)
    review_by_customer = db.Column(db.String(80), nullable=True)
    service = db.relationship('HouseholdServices', back_populates='request')
    customer = db.relationship('User', back_populates='customer_requests', foreign_keys=[customer_id])
    service_proffessional = db.relationship('User', back_populates='service_proffessional_requests', foreign_keys=[service_proffessional_id])

#Create a func to ceate an admin
def create_admin():
    with app.app_context(): 
        admin_user = User.query.filter_by(role = 'admin').first()
        if admin_user is None:
            admin_user = User(user_name='admin', password=generate_password_hash('admin'), role='admin', is_approved=True)
            db.session.add(admin_user)
            db.session.commit()
            print('Admin user created')

with app.app_context(): 
    #db.drop_all()
    db.create_all()
    create_admin()


#ROUTES
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

#LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        user_name = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(user_name=user_name).first()
        #print(user)
        if user and check_password_hash(user.password, password) and user.is_blocked == False:
            session['user_id'] = user.id
            session['role'] = user.role
            session['user_name'] = user.user_name
            if user.role == 'customer':
                flash('Login successful', 'success', )
                return redirect('/'+user.role+'_dashboard')
            elif user.role == 'service_proff':
                if user.is_approved == False and user.is_rejected == True:
                    flash('Your account has been rejected. Please contact admin', 'danger')
                    return redirect('/login')
                if user.is_approved == False:
                    flash('Please wait for admin approval', 'danger')
                    return redirect('/login')
                if user.service_id is None:
                    flash('Your service is not available. Please create a new account with other service', 'danger')
                    return redirect('/login')
                return redirect('/'+user.role+'_dashboard')
        elif user.is_blocked == True:
            flash('Your account has been blocked. Please contact admin', 'danger')
            return redirect('/login')
        else:
            flash('Login failed. Invalid username or password', 'danger')
            return redirect('/login')
    return render_template('base.html')    
        
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    if request.method == 'POST':    
        user_name = request.form['user_name']
        password = request.form['password'] 
        admin = User.query.filter_by(role='admin', user_name=user_name).first() #if >1 admin exists, so filtering by username too.
        if admin and check_password_hash(admin.password, password):
            session['user_name'] = user_name
            session['role'] = 'admin'
            flash('Admin logged in successfully', 'success')
            return redirect('/admin_dashboard') #if we need to redirect to a func, we use url_for, like u can use redirect(url_for(admin_dashboard))
        else:
            flash('Invalid username or password', 'danger')
            return render_template('admin_login.html', error='Invalid username or password')        

#REGISTRATION

#CUSTOMER REGISTRATION
@app.route('/customer_register', methods=['GET', 'POST'])
def customer_register():
    if request.method == 'GET':
        return render_template('customer_register.html')
    if request.method == 'POST':
        user_name = request.form['user_name']
        password = request.form['password']
        address = request.form['address']
        pincode = request.form['pincode']
        user = User.query.filter_by(user_name=user_name, role='customer').first()
        if user:
            flash('User already exists', 'danger')
            return redirect('/customer_register', error='User already exists')
        else:
            new_user = User(user_name=user_name, password=generate_password_hash(password), address=address, pincode=pincode, role='customer', is_approved=True)
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully. Please login', 'success')
            return redirect('/login')

#PROFF REGISTER
@app.route('/service_proff_register', methods=['GET', 'POST'])
def service_proff_register():
    if request.method == 'GET':
        services = HouseholdServices.query.all() #to show all services
        return render_template('service_proff_register.html', services=services)
    if request.method == 'POST':
        user_name = request.form['username']
        password = request.form['password']
        address = request.form['address']
        pincode = request.form['pincode']
        service_proffesional_file = request.files['service_proffesional_file']
        service_proffesional_experience = request.form['service_proffesional_experience']
        service = request.form['service'].strip()
        #print(service)
        service_id = HouseholdServices.query.filter_by(service_name=service).first().id
        user = User.query.filter_by(user_name=user_name, role='service_proff').first()
        if user:
            flash('User already exists. Please choose a different username', 'danger')
            return redirect('/service_proff_register')
        file_name = secure_filename(service_proffesional_file.filename)
        if file_name != '':
            file_ext = os.path.splitext(file_name)[1]
            renamed_file = user_name+file_ext
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            service_proffesional_file.save(os.path.join(app.config['UPLOAD_PATH'], renamed_file))
        new_user = User(user_name=user_name, password=generate_password_hash(password), address=address, pincode=pincode, role='service_proff', service_proffesional_experience=service_proffesional_experience, service_proffessional_file=renamed_file, service_id=service_id)
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully. Please wait for admin approval', 'success')
        return redirect('/login') 

# DASHBOARDS

#ADMIN DASHBOARD
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    services = HouseholdServices.query.all()
    requests = HouseholdServiceRequest.query.all()
    unapproved_proffessionals = User.query.filter(User.role == 'service_proff', User.is_approved==False, User.is_rejected==False).all()
    return render_template('admin_dashboard.html', services=services, requests=requests, unapproved_proffessionals=unapproved_proffessionals, admin_name=session['user_name'])  

#ADMIN FUNCTIONALITIES

#ADMIN CREATE SERVICE
@app.route('/admin_dashboard/create_service', methods=['GET', 'POST'])
def create_service():
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    if request.method == 'GET':
        return render_template('create_service.html')
    if request.method == 'POST':
        service_name = request.form['service_name']
        service_description = request.form['service_description']
        base_price = request.form['base_price']
        time_required = request.form['time_required']
        new_service = HouseholdServices(service_name=service_name, service_description=service_description, base_price=base_price, time_required=time_required)
        db.session.add(new_service)
        db.session.commit()
        flash('Service created successfully', 'success')
        return redirect('/admin_dashboard')
    
#ADMIN EDIT SERVICE
@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    service = HouseholdServices.query.get(service_id)
    if service is None:
        flash('Service not found', 'danger')
        return redirect('/admin_dashboard')
    if request.method == 'GET':
        return render_template('edit_service.html', service=service)
    if request.method == 'POST':
        service_name = request.form['service_name']
        service_description = request.form['service_description']
        base_price = request.form['base_price']
        time_required = request.form['time_required']
        service.service_name = service_name
        service.service_description = service_description
        service.base_price = base_price
        service.time_required = time_required
        db.session.commit()
        flash('Service updated successfully', 'success')
        return redirect('/admin_dashboard') 

#ADMIN DELETE SERVICE
@app.route('/delete_service/<int:service_id>', methods=['GET'])
def delete_service(service_id):
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    service = HouseholdServices.query.get(service_id)
    if service is None:
        flash('Service not found', 'danger')
        return redirect('/admin_dashboard')
    approved_proff = User.query.filter_by(role='service_proff', service_id=service_id, is_approved=True).all()
    for proff in approved_proff:
        proff.is_approved = False
        db.session.commit()
    # Check if there are any approved service professionals for the service
    #approved_proff = User.query.filter_by(role='service_proff', service_id=service_id, is_approved=True).first()
    if approved_proff:
        flash('Cannot delete service because there are approved service professionals assigned', 'danger')
        return redirect('/admin_dashboard')
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully', 'success')
    return redirect('/admin_dashboard') 

#APPROVE SERVICE PROFFESIONAL
@app.route('/approve_service_proffessional/<int:proffessional_id>', methods=['GET', 'POST'])
def approve_service_proffessional(proffessional_id):
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    proffessional = User.query.get_or_404(proffessional_id)
    proffessional.is_approved = True
    db.session.commit()
    flash('Service proffessional approved successfully', 'success')
    return redirect('/admin_dashboard')  

#REJECT SERVICE PROFFESIONAL
@app.route('/reject_service_proffessional/<int:proffessional_id>', methods=['GET', 'POST'])
def reject_service_proffessional(proffessional_id):
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')    
        return redirect('/login')
    proffessional = User.query.get_or_404(proffessional_id)
    pdf_file = proffessional.service_proffessional_file
    if pdf_file:
        path_file = os.path.join(app.config['UPLOAD_PATH'], pdf_file)
        if os.path.exists(path_file):
            try:
                os.remove(path_file)
                print('File deleted successfully')
            except Exception as e:
                print('Error: ', e)
        else:
            print('File not found')
    proffessional.is_approved = False 
    proffessional.is_rejected = True       
    db.session.commit()                
    flash('Service proffessional rejected successfully', 'success')
    return redirect('/admin_dashboard')

#VIEW SERVICE PROFFESIONAL
@app.route('/view_service_proffessional/<int:proffessional_id>', methods=['GET', 'POST'])
def view_service_proffessional(proffessional_id):
        if not session.get('role') == 'admin':
            flash('You are not authorized to access this page', 'danger')
            return redirect('/login')
        proffessional = User.query.get_or_404(proffessional_id)
        return render_template('view_service_proffessional.html', proffessional=proffessional,  service_proffessional=proffessional)

#ADMIN SUMMARY
@app.route('/admin_dashboard/summary', methods=['GET'])
def admin_summary():
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    customer_count = User.query.filter_by(role='customer').count()
    service_proffessional_count = User.query.filter_by(role='service_proff', is_approved=True, is_blocked=False).count()
    accepted_request_count = HouseholdServiceRequest.query.filter_by(status='accepted').count()
    rejected_request_count = HouseholdServiceRequest.query.filter_by(status='rejected').count()
    closed_request_count = HouseholdServiceRequest.query.filter_by(status='closed').count()
    pending_request_count = HouseholdServiceRequest.query.filter_by(status='pending').count()

    #image_1 : Number of users by role
    image_1 = os.path.join(curr_dir, 'static', 'images', 'image_1.png')
    roles = ['Customers', 'Service Proffessionals']
    count = [customer_count, service_proffessional_count]
    plt.clf()
    plt.figure(figsize=(8, 6), dpi=100, facecolor='w') #figsize: a tuple specifying the figure's width and height in inches, dpi: the figure's resolution in dots per inch, facecolor: the figure's background color.
    sns.barplot(x=roles, y=count)
    plt.title('Number of users by role')
    plt.xlabel('User Roles')
    plt.ylabel('Count')
    plt.savefig(image_1, format='png')
    plt.close()

    #image_2 : Request status by count
    image_2 = os.path.join(curr_dir, 'static', 'images', 'image_2.png')
    status = ['Accepted requests', 'Rejected requests', 'Closed requests', 'Pending requests']
    count = [accepted_request_count, rejected_request_count, closed_request_count, pending_request_count]
    plt.clf() #to create a new figure (avoid overlapping plots or residual elements from previous plots.)
    plt.figure(figsize=(8, 6))
    plt.pie(count, labels=status, autopct='%1.1f%%', colors=['#4caf50', '#f44336', '#ff9800', '#2196f3'], shadow=True, startangle=90)
    plt.title('Number of requests by status')
    plt.savefig(image_2, format='png')
    plt.close()
    return render_template('admin_summary.html', customer_count=customer_count, service_proffessional_count=service_proffessional_count, accepted_request_count=accepted_request_count, rejected_request_count=rejected_request_count, closed_request_count=closed_request_count, pending_request_count=pending_request_count)

# ADMIN SEARCH
@app.route('/admin_dashboard/search', methods=['GET'])
def admin_search():
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/admin')
    search_by = request.args.get('search_by') #request?==>search_by Like that. Cuz form is using GET method
    search_term = request.args.get('search_term')
    if search_term:
        if search_by == 'user_name':
            users = User.query.filter(User.user_name.contains(search_term)).all()
            return render_template('admin_search.html', users=users)
        elif search_by == 'service':
            services = HouseholdServices.query.filter(HouseholdServices.service_name.contains(search_term)).all()
            return render_template('admin_search.html', services=services) 
    else:
        users = User.query.all()
        services = HouseholdServices.query.all()
        return render_template('admin_search.html', users=users, services=services)
    
    
#ADMIN BLOCK / UNBLOCK
@app.route('/admin_dashboard/block_user/<int:user_id>', methods=['GET', 'POST'])
def block_user(user_id):
    if not session.get('role') == 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    user = User.query.get_or_404(user_id)
    if user.is_blocked == True:
        user.is_blocked = False
        db.session.commit()
        flash('User unblocked successfully', 'success')
    else:
        user.is_blocked = True
        db.session.commit()
        flash('User blocked successfully', 'success')
    return redirect('/admin_dashboard/search')


#CUSTOMER DASHBOARD
@app.route('/customer_dashboard', methods=['GET', 'POST'])
def customer_dashboard():
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    customer = User.query.filter_by(user_name=session['user_name']).first()
    services = HouseholdServices.query.join(User).filter(User.is_approved == True).all() #filter_by only works when there's only 1 table being queried, join using cond defined while db creation
    service_history = HouseholdServiceRequest.query.filter_by(customer_id=customer.id).all() #need to revisit later
    return render_template('customer_dashboard.html', customer=customer, services=services, service_history=service_history)

#CUSTOMER FUNCTIONALITIES

#CUSTOMER CREATE SERVICE REQUEST
@app.route('/customer_dashboard/create_request/<int:service_id>', methods=['GET', 'POST'])
def create_request(service_id):
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    customer = User.query.filter_by(user_name=session['user_name']).first()
    service = HouseholdServices.query.get_or_404(service_id)
    service_proff = User.query.filter_by(role='service_proff', service_id=service_id, is_approved=True, is_rejected=False).all()
    if request.method == 'POST':
        if service is None:
            flash('Service not found', 'danger')
            return redirect('/customer_dashboard')
        service_request = HouseholdServiceRequest(customer_id=customer.id, service_proffessional_id=User.query.filter_by(user_name=request.form['service_proff_name'], is_approved=True, is_rejected=False).first().id, service_id=service.id, status='pending', description=request.form['request_description'])
        db.session.add(service_request)
        db.session.commit()
        flash('Service request created successfully', 'success')
        return redirect('/customer_dashboard')
    return render_template('create_request.html', service_proff=service_proff, service=service) # GET Method

#CUSTOMER EDIT A SERVICE REQUEST
@app.route('/customer_dashboard/edit_request/<int:service_request_id>', methods=['GET', 'POST'])
def edit_request(service_request_id):
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')    
        return redirect('/login')
    service_request = HouseholdServiceRequest.query.get_or_404(service_request_id)
    if request.method == 'POST':
        if service_request.status == 'pending': #so that only pending requests can be edited, not closed or other requests.
            description = request.form['description']
            service_request.description = description
            db.session.commit()
            flash('Service request updated successfully', 'success')
            return redirect('/customer_dashboard')
        else:
            flash('Service request cannot be edited', 'danger')
            return redirect('/customer_dashboard')
    return render_template('edit_request.html', service_request=service_request)

#CUSTOMER DELETE A SERVICE REQUEST
@app.route('/customer_dashboard/delete_request/<int:service_request_id>', methods=['GET', 'POST'])
def delete_request(service_request_id):
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    service_request = HouseholdServiceRequest.query.get_or_404(service_request_id)
    db.session.delete(service_request)
    db.session.commit()
    flash('Service request deleted successfully', 'success')
    return redirect('/customer_dashboard') 

#CUSTOMER SEARCH
@app.route('/customer_dashboard/search', methods=['GET', 'POST'])
def customer_search():
    if request.method == 'GET':
        if not session.get('role') == 'customer':
            flash('You are not authorized to access this page', 'danger')
            return redirect('/login')
        services = HouseholdServices.query.join(User).filter(User.is_approved == True, User.is_rejected == False, User.is_blocked == False).all()
        return render_template('customer_search.html', services=services, customer_name=session['user_name'])
    if request.method == 'POST':
        if not session.get('role') == 'customer':
            flash('You are not authorized to access this page', 'danger')
            return redirect('/login')
        search_by = request.form['search_by']
        search_term = request.form['search_term']
        if search_term:
            if search_by == 'service_name':
                services = HouseholdServices.query.join(User).filter(User.user_name.contains(search_term), User.is_approved == True, User.is_rejected == False, User.is_blocked == False).all() #contains is a case sensitive search
            elif search_by == 'pincode':
                services = HouseholdServices.query.join(User).filter(User.pincode == search_term).all()
            elif search_by == 'service_proff_user_name':
                services = HouseholdServices.query.join(User).filter(User.user_name.contains(search_term), User.is_approved == True, User.is_rejected == False, User.is_blocked == False).all()
            elif search_by == 'base_price':
                services = HouseholdServices.query.filter(HouseholdServices.base_price.contains(search_term)).all()
            elif search_by == 'time_required':
                services = HouseholdServices.query.filter(HouseholdServices.time_required.contains(search_term)).all()
        else:
            services = HouseholdServices.query.join(User).filter(User.is_approved == True, User.is_rejected == False, User.is_blocked == False).all()
        return render_template('customer_search.html', services=services, customer_name=session['user_name'])
    
#CUSTOMER CLOSE SERVICE REQUEST
@app.route('/customer_dashboard/close_request/<int:service_request_id>', methods=['GET', 'POST'])  
def close_request(service_request_id):
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    if request.method == 'GET':
        req = HouseholdServiceRequest.query.get_or_404(service_request_id)
        if not req:
            flash('Service request not found', 'danger')
            return redirect('/customer_dashboard')
        #req.status = 'closed'
        #db.session.commit()
        #flash('Service request closed successfully', 'success')
        return render_template('rating_review.html', req=req)  
    elif request.method == 'POST':
        req = HouseholdServiceRequest.query.get_or_404(service_request_id)
        req.status = 'closed'
        req.rating_by_customer = request.form['rating']
        req.review_by_customer = request.form['review']
        req.date_closed = datetime.now().date()

        proff_review_update = User.query.get_or_404(req.service_proffessional_id)
        temp = proff_review_update.rating_count
        proff_review_update.rating_count = temp + 1
        proff_review_update.avg_rating = (int(proff_review_update.avg_rating) * int(proff_review_update.rating_count) + int(req.rating_by_customer)) / (int(proff_review_update.rating_count) + 1)
        db.session.commit()
        flash('Service request closed successfully', 'success')
        return redirect('/customer_dashboard')
    
#CUSTOMER SUMMARY    
@app.route('/customer_dashboard/summary', methods=['GET']) 
def customer_summary():
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    customer_id = User.query.filter_by(user_name=session['user_name']).first().id
    customer = User.query.get_or_404(customer_id)
    pending_request_count = HouseholdServiceRequest.query.filter_by(customer_id=customer.id, status='pending').count()
    accepted_request_count = HouseholdServiceRequest.query.filter_by(customer_id=customer.id, status='accepted').count()
    rejected_request_count = HouseholdServiceRequest.query.filter_by(customer_id=customer.id, status='rejected').count()
    closed_request_count = HouseholdServiceRequest.query.filter_by(customer_id=customer.id, status='closed').count()
    image_3 = os.path.join(curr_dir, 'static', 'images', 'image_3.png')
    status = ['Pending requests', 'Accepted requests', 'Rejected requests', 'Closed requests']
    count = [pending_request_count, accepted_request_count, rejected_request_count, closed_request_count]
    plt.clf()
    plt.figure(figsize=(8, 6))
    plt.pie(count, labels=status, autopct='%1.1f%%', colors=['#4caf50', '#f44336', '#ff9800', '#2196f3'], shadow=True, startangle=90)
    plt.title('Number of requests by status')
    plt.savefig(image_3, format='png')
    plt.close()
    return render_template('customer_summary.html', customer=customer, pending_request_count=pending_request_count, accepted_request_count=accepted_request_count, rejected_request_count=rejected_request_count, closed_request_count=closed_request_count)    
        
#CUSTOMER PROFF VIEW
@app.route('/customer_dashboard/view_service_proffessional/<int:proff_id>', methods=['GET', 'POST'])
def cust_view_service_proffessional(proff_id):
    if not session.get('role') == 'customer':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    proff = User.query.get_or_404(proff_id)
    reviews = HouseholdServiceRequest.query.filter_by(service_proffessional_id=proff_id, status='closed').all()
    return render_template('cust_view_service_proffessional.html', proff=proff, reviews=reviews)

#PROFF DASHBOARD
@app.route('/service_proff_dashboard', methods=['GET', 'POST'])
def service_proff_dashboard():
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    sid = User.query.filter_by(user_name=session['user_name']).first().id
    service_proff = User.query.filter_by(id=sid, role='service_proff').first()
    if service_proff.is_approved == False:
        flash('Please wait for admin approval', 'danger')
        return redirect('/login')
    elif service_proff.is_rejected == True:
        flash('Your account has been rejected. Please contact admin', 'danger')
        return redirect('/login')
    pending_requests = HouseholdServiceRequest.query.filter_by(service_proffessional_id=sid, status='pending').all()
    accepted_requests = HouseholdServiceRequest.query.filter_by(service_proffessional_id=sid, status='accepted').all()
    closed_requests = HouseholdServiceRequest.query.filter_by(service_proffessional_id=sid, status='closed').all()
    return render_template('service_proff_dashboard.html', service_proff=service_proff, pending_requests=pending_requests, accepted_requests=accepted_requests, closed_requests=closed_requests)

#PROFF ACCEPT SERVICE REQUEST
@app.route('/service_proff_dashboard/accept_request/<int:request_id>', methods=['GET'])
def accept_request(request_id):
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    new_request = HouseholdServiceRequest.query.get_or_404(request_id) #get searches with prim key only
    new_request.status = 'accepted'
    db.session.commit()
    flash('Service request accepted successfully', 'success')
    return redirect('/service_proff_dashboard')

#PROFF REJECT SERVICE REQUEST
@app.route('/service_proff_dashboard/reject_request/<int:request_id>', methods=['GET'])
def reject_request(request_id):
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    new_request = HouseholdServiceRequest.query.get_or_404(request_id) #get searches with prim key only
    new_request.status = 'rejected'
    db.session.commit()
    flash('Service request rejected successfully', 'success')    
    return redirect('/service_proff_dashboard')

#PROFF EDIT SERVICE
@app.route('/service_proff_dashboard/edit_service', methods=['GET', 'POST'])
def service_edit_service():
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    proff = User.query.filter_by(user_name=session['user_name']).first()
    service_id = proff.service_id
    service = HouseholdServices.query.filter_by(id = service_id).first()
    if request.method == 'GET':
        return render_template('service_proff_edit_service.html', service=service)
    if request.method == 'POST':
        set_price = request.form['base_price']
        if int(service.base_price) < int(set_price):
            #print(set_price , service.base_price)
            service.base_price = set_price
            db.session.commit()
            flash('Service updated successfully', 'success')
            return redirect('/service_proff_dashboard')
        else:
             #print(set_price , service.base_price, 'else')
             flash('Service price cannot be less than or equal to base price', 'danger')
             return redirect(url_for('service_edit_service'))

#PROFF SEARCH
@app.route('/service_proff_dashboard/search', methods=['GET', 'POST'])
def service_proff_search():
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    service_proff = User.query.filter_by(user_name=session['user_name']).first()
    if request.method == 'GET':
        service_request = HouseholdServiceRequest.query.join(User, onclause=HouseholdServiceRequest.customer_id == User.id).filter(User.role == 'customer',HouseholdServiceRequest.service_id == service_proff.service_id).all()
        return render_template('service_proff_search.html', service_request=service_request, customer_name=session['user_name'])
    if request.method == 'POST':
        search_by = request.form['search_by'] #pincode, address & status
        search_term = request.form['search_term']
        if search_term: 
            if search_by == 'pincode':
                service_request = HouseholdServiceRequest.query.join(User, onclause=HouseholdServiceRequest.customer_id == User.id).filter(User.role == 'customer', User.pincode == search_term, HouseholdServiceRequest.service_id == service_proff.service_id).all()
            elif search_by == 'address':
                service_request = HouseholdServiceRequest.query.join(User, onclause=HouseholdServiceRequest.customer_id == User.id).filter(User.role == 'customer', User.address.contains(search_term), HouseholdServiceRequest.service_id == service_proff.service_id).all()
            elif search_by == 'status':
                service_request = HouseholdServiceRequest.query.join(User, onclause=HouseholdServiceRequest.customer_id == User.id).filter(User.role == 'customer', HouseholdServiceRequest.status.contains(search_term), HouseholdServiceRequest.service_id == service_proff.service_id).all()    
        else:
            service_request = HouseholdServiceRequest.query.join(User, onclause=HouseholdServiceRequest.customer_id == User.id).filter(User.role == 'customer',HouseholdServiceRequest.service_id == service_proff.service_id).all()
        return render_template('service_proff_search.html', service_request = service_request, customer_name=session['user_name'])              

#PROFF SUMMARY   
@app.route('/service_proff_dashboard/summary', methods=['GET']) 
def service_proff_summary():
    if not session.get('role') == 'service_proff':
        flash('You are not authorized to access this page', 'danger')
        return redirect('/login')
    proff_id = User.query.filter_by(user_name=session['user_name']).first().id
    proff = User.query.get_or_404(proff_id)
    pending_request_count = HouseholdServiceRequest.query.filter_by(service_proffessional_id=proff.id, status='pending').count()
    accepted_request_count = HouseholdServiceRequest.query.filter_by(service_proffessional_id=proff.id, status='accepted').count()
    rejected_request_count = HouseholdServiceRequest.query.filter_by(service_proffessional_id=proff.id, status='rejected').count()
    closed_request_count = HouseholdServiceRequest.query.filter_by(service_proffessional_id=proff.id, status='closed').count()
    image_4 = os.path.join(curr_dir, 'static', 'images', 'image_4.png')
    status = ['Pending requests', 'Accepted requests', 'Rejected requests', 'Closed requests']
    count = [pending_request_count, accepted_request_count, rejected_request_count, closed_request_count]
    plt.clf()
    plt.figure(figsize=(8, 6))
    plt.pie(count, labels=status, autopct='%1.1f%%', colors=['#4caf50', '#f44336', '#ff9800', '#2196f3'], shadow=True, startangle=90)
    plt.title('Number of requests by status')
    plt.savefig(image_4, format='png')
    plt.close()
    return render_template('service_proff_summary.html', proff=proff, pending_request_count=pending_request_count, accepted_request_count=accepted_request_count, rejected_request_count=rejected_request_count, closed_request_count=closed_request_count)

#LOGOUT
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user_name', None)
    session.pop('role', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__': #if my app is running in them main file only, then only run this. Other terminal se run nhi hoga. If it's imported to some other file and then ran, it won't run from there.
    app.run(debug=True)
