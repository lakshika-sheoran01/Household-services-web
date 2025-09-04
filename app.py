import os             
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask,render_template,url_for, redirect,request,abort,flash,session
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy         
from sqlalchemy import func
import matplotlib.pyplot as plt
import io
import base64
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.ticker import MaxNLocator 

#--------------------------------------------------------------------Configuration--------------------------------------------------------------------------#



curr_dir=os.path.dirname(os.path.abspath(__file__))  

app=Flask(__name__)  
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///household_services_database.sqlite3'
app.config['SQLALCHEMY_TRACK_M0DIFICATIONS']=False
app.config['PASSWORD_HASH']='@sheoran'
app.secret_key='household'

app.config['UPLOAD_EXTENSIONS']=['.pdf']
app.config['UPLOAD_PATH']=os.path.join(curr_dir,'static')
db=SQLAlchemy()

db.init_app(app)
app.app_context().push()
app.config['UPLOAD_FOLDER'] = 'static'

#--------------------------------------------------------------------Models--------------------------------------------------------------------------#

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(72), unique=True, nullable=False)
    user_password = db.Column(db.String(67), nullable=False)
    user_address = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.Integer, nullable=True)
    admin_status = db.Column(db.Boolean, default=False)
    professional_status = db.Column(db.Boolean, default=False)
    customer_status = db.Column(db.Boolean, default=False)
    approval_status = db.Column(db.Boolean, default=False)
    rating_total = db.Column(db.Integer, default=0)
    average_rating = db.Column(db.Float, default=0.0)
    professional_document = db.Column(db.String(100), nullable=True)
    professional_experience_level = db.Column(db.String(10), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('householdServices.id', ondelete="SET NULL"), nullable=True)
    
    service = db.relationship('HouseholdServices', back_populates="professionals", foreign_keys=[service_id])
    professional_requests = db.relationship('HouseholdRequest', back_populates="professional", foreign_keys="HouseholdRequest.professional_id")
    customer_requests = db.relationship('HouseholdRequest', back_populates="customer", foreign_keys="HouseholdRequest.client_id")


class HouseholdServices(db.Model):
    __tablename__ = "householdServices"
    id = db.Column(db.Integer, primary_key=True)
    service_title = db.Column(db.String(30), unique=True, nullable=False)
    service_details = db.Column(db.String(40), nullable=True)
    duration_required = db.Column(db.String(30), nullable=True)
    starting_price = db.Column(db.Integer, nullable=True)
    
    professionals = db.relationship('User', back_populates="service", cascade="all, delete", foreign_keys="User.service_id")
    requests = db.relationship('HouseholdRequest', back_populates="service", cascade="all, delete")


class HouseholdRequest(db.Model):
    __tablename__ = "householdRequest"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('householdServices.id'), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  
    request_type = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text, nullable=True)
    request_status = db.Column(db.String(56), nullable=True)
    created_at = db.Column(db.Date, nullable=False, default=datetime.now().date())
    closed_at = db.Column(db.Date, nullable=True)
    customer_rating = db.Column(db.Float, default=0.0)
    customer_review = db.Column(db.String(20), nullable=True)
    
    service = db.relationship('HouseholdServices', back_populates='requests')
    customer = db.relationship('User', back_populates='customer_requests', foreign_keys=[client_id])
    professional = db.relationship('User', back_populates='professional_requests', foreign_keys=[professional_id])  




#--------------------------------------------------------------------create admin--------------------------------------------------------------------------#


def create_admin():
    with app.app_context():
        admin_user = User.query.filter_by(admin_status=True).first()
        if not admin_user:
            admin_user = User(
                username="admin",
                user_password=generate_password_hash('pass'),
                admin_status=True 
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully")

with app.app_context():
    db.create_all() 
    create_admin()



#-------------------------------------------------------------------- Route --------------------------------------------------------------------------#

@app.route("/")
def hello():
    return render_template('index.html')

#-------------------------------------------------------------------- Admin Routes --------------------------------------------------------------------------#


@app.route("/admin/authenticate", methods=['GET', 'POST'])
def admin_authenticate():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        admin = User.query.filter_by(admin_status=True, username=username).first()
        if admin and check_password_hash(admin.user_password, password):
            session['username'] = admin.username
            session['is_admin'] = True
            flash("Logged in successfully", 'success')
            return redirect("/admin/dashboard")
        flash("Invalid credentials. Please try again.", 'danger')
    return render_template('adminlogin.html')



@app.route("/admin/dashboard", methods=["GET", "POST"])
def admindashboard():
    if not session.get('is_admin'):
        flash('Please log in as an admin first.', 'danger')
        return redirect('/admin/authenticate')

    
    services = HouseholdServices.query.all()
    requests = HouseholdRequest.query.all()
    unapproved_professionals = User.query.filter_by(approval_status=False, professional_status=True).all()

    return render_template(
        'admin_dashboard.html',
        services=services,
        requests=requests,
        admin_name=session['username'],
        unapproved_professionals=unapproved_professionals
    )



from sqlalchemy.exc import IntegrityError

@app.route("/admin/service/create", methods=["GET", "POST"])
def create_service():
    if not session.get('is_admin'):
        flash('Please log in as an admin first.', 'danger')
        return redirect('/admin/authenticate')

    if request.method == 'POST':
        service_title = request.form['service_title']
        service_details = request.form['service_details']
        starting_price = request.form['starting_price']
        duration_required = request.form['duration_required']
        existing_service = HouseholdServices.query.filter_by(service_title=service_title).first()
        if existing_service:
            flash(f"A service with the title '{service_title}' already exists.", 'warning')
            return redirect('/admin/dashboard')

        try:
            new_service = HouseholdServices(
                service_title=service_title,
                service_details=service_details,
                starting_price=starting_price,
                duration_required=duration_required
            )
            db.session.add(new_service)
            db.session.commit()
            flash('Service created successfully.', 'success')
            return redirect('/admin/dashboard')
        except IntegrityError:
            db.session.rollback()  
            flash('An error occurred while adding the service. Please try again.', 'danger')

        return redirect('/admin/dashboard')


@app.route("/admin/service/delete/<int:service_id>", methods=["POST", "GET"])
def delete_service(service_id):
    if not session.get('is_admin'):
        flash('Please log in as an admin first.', 'danger')
        return redirect('/admin/authenticate')

    
    service = HouseholdServices.query.get_or_404(service_id)

    
    approved_professionals = User.query.filter_by(professional_status=True, approval_status=True, service_id=service_id).all()
    for professional in approved_professionals:
        professional.approval_status = False

  
    db.session.delete(service)
    db.session.commit()

    return redirect('/admin/dashboard')


@app.route("/admin/service/edit/<int:service_id>", methods=["GET", "POST"])
def edit_service(service_id):
    if not session.get('is_admin'):
        flash('Please log in as an admin first.', 'danger')
        return redirect('/admin/authenticate')
    service = HouseholdServices.query.get_or_404(service_id)

    if request.method == "POST":
        service.service_title = request.form['service_title']
        service.service_details = request.form['service_details']
        service.starting_price = request.form['starting_price']
        service.duration_required = request.form['duration_required']
        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('edit_service.html', service=service)



@app.route("/admin_dashboard/view_professional/<int:professional_id>", methods=["GET", "POST"])
def view_professional(professional_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/login')
    professional = User.query.get_or_404(professional_id)
    return render_template('view_professional.html', professional=professional)


@app.route("/admin_dashboard/approve_professional/<int:professional_id>")
def approve_professional(professional_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/login')
    professional = User.query.get_or_404(professional_id)
    professional.approval_status = True
    db.session.commit()
    flash('Professional approved successfully', 'success')
    return redirect('/admin/dashboard')


@app.route("/admin_dashboard/reject_professional/<int:professional_id>")
def reject_professional(professional_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/login')
    professional = User.query.get_or_404(professional_id)
    document_file = professional.professional_document
    if document_file:
        file_path = os.path.join(app.config['UPLOAD_PATH'], document_file)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print('File deleted successfully')
            except Exception as e:
                print(f'Error deleting file: {e}')
        else:
            print('File not found')
    db.session.delete(professional)
    db.session.commit()
    flash('Professional rejected successfully', 'success')
    return redirect('/admin/dashboard')


@app.route('/admin/search', methods=['GET', 'POST'])
def search_users():
    users = None
    if request.method == 'POST':
        username = request.form.get('username')
        approval_status = request.form.get('approval_status')
        query = User.query.filter_by(admin_status=False)
        if username:
            query = query.filter(User.username.ilike(f"%{username}%"))
        if approval_status == "approved":
            query = query.filter_by(approval_status=True)
        elif approval_status == "not_approved":
            query = query.filter_by(approval_status=False)
        users = query.all()
    
    return render_template('admin_search.html', users=users)


@app.route('/admin/flag/<int:user_id>', methods=['POST'])
def flag_user(user_id):
    user = User.query.filter_by(id=user_id, admin_status=False).first_or_404()
    flag = request.form.get('flag') == 'true'
    user.approval_status = flag
    db.session.commit()
    action = "approved" if flag else "flagged"
    return redirect(url_for('search_users'))



@app.route('/admin/stats')
def admin_statistics():
    if not session.get('is_admin'):
        return "Unauthorized", 403 
    total_users = User.query.filter_by(admin_status=False).count()
    total_requests = HouseholdRequest.query.count()
    approved_users = User.query.filter_by(approval_status=True, admin_status=False).count()
    flagged_users = User.query.filter_by(approval_status=False, admin_status=False).count()
    avg_rating_professionals = db.session.query(func.avg(User.average_rating)) \
        .filter(User.professional_status == True, User.admin_status == False).scalar()

    total_services_provided = HouseholdRequest.query.filter(HouseholdRequest.request_status == "Closed").count()

    fig1, ax1 = plt.subplots()
    ax1.pie([approved_users, flagged_users], 
            labels=['Approved', 'Flagged'], 
            autopct='%1.1f%%', 
            startangle=90, 
            colors=['#28a745', '#dc3545'])
    ax1.axis('equal')  
    ax1.set_title('Approved vs Flagged Users')

    user_status_chart = io.BytesIO()
    FigureCanvas(fig1).print_png(user_status_chart)
    user_status_chart.seek(0)
    user_status_chart_base64 = base64.b64encode(user_status_chart.getvalue()).decode('utf-8')

    services = HouseholdServices.query.all()
    service_data = {service.service_title: HouseholdRequest.query.filter_by(service_id=service.id).count()
                    for service in services}
    fig2, ax2 = plt.subplots()
    ax2.bar(service_data.keys(), service_data.values(), color='blue')
    ax2.set_ylabel('Number of Requests')
    ax2.yaxis.set_major_locator(MaxNLocator(integer=True)) 

    bar_chart = io.BytesIO()
    FigureCanvas(fig2).print_png(bar_chart)
    bar_chart.seek(0)
    bar_chart_base64 = base64.b64encode(bar_chart.getvalue()).decode('utf-8')

    stats_data = {
        'total_users': total_users,
        'total_requests': total_requests,
        'approved_users': approved_users,
        'flagged_users': flagged_users,
        'avg_rating_professionals': avg_rating_professionals if avg_rating_professionals is not None else 0,
        'total_services_provided': total_services_provided,
        'user_status_chart': user_status_chart_base64,
        'bar_chart': bar_chart_base64
    }

    return render_template('admin_stats.html', stats_data=stats_data)



#-------------------------------------------------------------------- Professional Routes --------------------------------------------------------------------------#



@app.route("/professional/register", methods=['GET', 'POST'])
def professional_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        professional_file = request.files['professional_file']
        professional_experience_level = request.form['professional_experience']
        postal_code = request.form['postal_code']
        service_title = request.form['service']
        service = HouseholdServices.query.filter_by(service_title=service_title).first()
        if not service:
            return redirect('/professional/register')
        service_id = service.id

        user = User.query.filter_by(username=username).first()
        if user:
            return redirect('/professional/register')

        file_name = secure_filename(professional_file.filename)
        if file_name:
            file_ext = os.path.splitext(file_name)[1]
            renamed_file_name = f"{username}{file_ext}"
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Invalid file type.', 'danger')
                return redirect('/professional/register')
            professional_file.save(os.path.join(app.config['UPLOAD_PATH'], renamed_file_name))
        else:
            renamed_file_name = None

        new_user = User(
            username=username,
            user_password=generate_password_hash(password),
            user_address=address,
            postal_code=postal_code,
            professional_document=renamed_file_name,
            professional_experience_level=professional_experience_level,
            service_id=service_id,
            professional_status=True, 
            approval_status=False 
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please wait for admin approval.', 'success')
        return redirect("/user/login")

    services = HouseholdServices.query.all()
    print(services)  

    return render_template('professional_reg.html', services=services)

@app.route("/professional/dashboard", methods=["GET", "POST"])
def professional_dashboard():
    services = HouseholdServices.query.all()
    for service in services:
        print(service.id, service.service_title)
    if not session.get('is_professional'):  
        flash('Please log in as a professional to access this page.', 'danger')
        return redirect('/user/login')

    professional = User.query.filter_by(username=session['username']).first()
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect('/user/login')

    if not professional.approval_status:
        flash('Please wait for admin approval.', 'danger')
        return redirect('/user/login')

    pending_requests = HouseholdRequest.query.filter_by(
        professional_id=professional.id, 
        request_status="Pending", 
        request_type='Private'
    ).all()
    accepted_requests = HouseholdRequest.query.filter_by(
        professional_id=professional.id, 
        request_status="Accepted"
    ).all()
    closed_requests = HouseholdRequest.query.filter_by(
        professional_id=professional.id, 
        request_status="Closed"
    ).all()

    return render_template(
        'professional_dashboard.html',
        professional=professional,
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        closed_requests=closed_requests
    )

@app.route('/professional/dashboard/edit_profile', methods=["GET", "POST"])
def edit_professional_profile():
    if not session.get('is_professional'):
        flash('Please log in as a professional to access this page.', 'danger')
        return redirect('/user/login') 

    professional = User.query.filter_by(username=session.get("username")).first()
    if not professional:
        flash('Professional account not found.', 'danger')
        return redirect('/user/login')

    if request.method == "POST":
        address = request.form.get('user_address')
        postal_code = request.form.get('postal_code').strip()
        experience_level = request.form.get('experience_level').strip()
        professional.user_address = address
        professional.postal_code = postal_code
        professional.professional_experience_level = experience_level
        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            return redirect('/professional/dashboard')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the profile: {str(e)}', 'danger')
            return redirect('/professional/dashboard/edit_profile')
    services = HouseholdServices.query.all()

    return render_template(
        'professional_dashboard.html',
        professional=professional,
        services=services
    )

@app.route("/professional/request/<int:request_id>/accept", methods=["POST"])
def accept_request(request_id):
    if not session.get('is_professional'):
        flash("Please log in as a professional.", "danger")
        return redirect("/user/login")
    service_request = HouseholdRequest.query.get_or_404(request_id)
    professional = User.query.filter_by(username=session['username']).first()

    if service_request.professional_id != professional.id:
        flash("Unauthorized action.", "danger")
        return redirect("/professional/dashboard")
    service_request.request_status = "Accepted"
    db.session.commit()

    return redirect("/professional/dashboard")


@app.route("/professional/request/<int:request_id>/reject", methods=["POST"])
def reject_request(request_id):
    if not session.get('is_professional'):
        flash("Please log in as a professional.", "danger")
        return redirect("/user/login")
    service_request = HouseholdRequest.query.get_or_404(request_id)
    professional = User.query.filter_by(username=session['username']).first()

    if service_request.professional_id != professional.id:
        flash("Unauthorized action.", "danger")
        return redirect("/professional/dashboard")
    service_request.request_status = "Rejected"
    db.session.commit()
    return redirect("/professional/dashboard")

@app.route('/professional/dashboard/search', methods=["GET", "POST"])
def view_service_requests():
    if not session.get('is_professional'):
        flash('You must log in as a professional to access this feature.', 'danger')
        return redirect('/login')
    professional = User.query.filter_by(username=session["username"]).first()

    if not professional or not professional.professional_status:
        flash('Unauthorized access. You must be a verified professional to view this page.', 'danger')
        return redirect('/login')
    query = HouseholdRequest.query.filter_by(professional_id=professional.id)

    if request.method == "POST":
        status_filter = request.form.get('status')
        date_filter = request.form.get('date')

        if status_filter:
            query = query.filter(HouseholdRequest.request_status == status_filter)

        if date_filter:
            try:
                parsed_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                query = query.filter(HouseholdRequest.created_at == parsed_date)
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')

    requests = query.order_by(HouseholdRequest.created_at.desc()).all()

    requests_data = []
    for req in requests:
        options = []
        if req.request_status == "Pending":
            options.append("Accept")
            options.append("Reject")
        requests_data.append({
            "id": req.id,
            "service_title": req.service.service_title,
            "client_name": req.customer.username,
            "details": req.details,
            "status": req.request_status,
            "created_at": req.created_at,
            "options": options
        })

    return render_template('professional_search.html', requests=requests_data)




#-------------------------------------------------------------------- Customer Login Routes --------------------------------------------------------------------------#

@app.route("/register/customer", methods=['GET', 'POST'])
def customer_register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        pin_code = request.form['postal_code']
        user = User.query.filter_by(username=username).first()
        if user:
            flash("User already exists. Please choose a different username.", 'danger')
            return redirect('/register/customer')
        new_user = User(
            username=username,
            user_password=generate_password_hash(password),
            customer_status=True, 
            approval_status=True,  
            user_address=address,
            postal_code=pin_code
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration Successful. Please log in.', 'success')
        return redirect('/user/login')
    
    return render_template('customer_reg.html')

@app.route("/customer/dashboard", methods=["GET", "POST"])
def customer_dashboard():
    if not session.get('is_customer'):
        flash('Please login first', 'danger')
        return redirect('/user/login')
    customer = User.query.filter_by(username=session["username"]).first()
    
    if not customer:
        flash('Customer not found.', 'danger')
        return redirect('/user/login')
    services = HouseholdServices.query.join(User, User.service_id == HouseholdServices.id).filter(User.approval_status == True).all()
    service_history = HouseholdRequest.query.filter_by(client_id=customer.id).filter(HouseholdRequest.professional_id.isnot(None)).all()

    return render_template('customer_dashboard.html', customer=customer, services=services, service_history=service_history)



@app.route('/customer/dashboard/edit_profile', methods=["GET", "POST"])
def edit_profile():
    if not session.get('is_customer'):
        flash('Please login first', 'danger')
        return redirect('/user/login')
    customer = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        address = request.form.get('address')
        postal_code = request.form.get('postal_code')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != customer.id:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect('/customer/dashboard/edit_profile')

        customer.username = username
        customer.user_password = generate_password_hash(password) 
        customer.user_address = address
        customer.postal_code = postal_code
        db.session.commit()

        flash('Profile updated successfully', 'success')
        return redirect('/customer/dashboard')
    return render_template('customer_dashboard.html', customer=customer)

@app.route('/customer/dashboard/service/<int:service_id>', methods=["GET", "POST"])
def request_service(service_id):
    if not session.get('is_customer'):
        flash('You must log in as a customer to access this feature.', 'danger')
        return redirect('/login')

    if request.method == "POST":
        professional_username = request.form.get('professional')
        request_details = request.form.get('details')
        professional = User.query.filter_by(username=professional_username, professional_status=True, approval_status=True).first()
        customer = User.query.filter_by(username=session["username"]).first()

        if not professional:
            flash("Selected professional is not available or not approved.", 'danger')
            return redirect(request.url)
        new_request = HouseholdRequest(
            client_id=customer.id,
            professional_id=professional.id,
            service_id=service_id,
            details=request_details,
            request_status="Pending",
            request_type="Private"
        )
        db.session.add(new_request)
        db.session.commit()

        flash(f"Your request has been sent to {professional_username} successfully!", 'success')
        return redirect(request.url)
    service = HouseholdServices.query.get_or_404(service_id)
    professionals = User.query.filter_by(professional_status=True, approval_status=True, service_id=service_id).all()
    return render_template('service.html', service=service, professionals=professionals)


@app.route("/customer/request/<int:request_id>/close", methods=["POST"])
def mark_as_done(request_id):
    if not session.get("is_customer"):
        flash("Please log in as a customer.", "danger")
        return redirect("/user/login")

    service_request = HouseholdRequest.query.get_or_404(request_id)
    if service_request.client_id != session.get("user_id"):
        flash("Unauthorized action.", "danger")
        return redirect("/customer/dashboard")

    service_request.request_status = "Closed"
    service_request.closed_at = datetime.now().date()
    db.session.commit()

    flash("Service marked as done successfully.", "success")
    return redirect("/customer/dashboard")

@app.route("/customer/request/<int:request_id>/rate", methods=["POST"])
def rate_service(request_id):
    if not session.get("is_customer"):
        flash("Please log in as a customer.", "danger")
        return redirect("/user/login")
    service_request = HouseholdRequest.query.get_or_404(request_id)
    rating = request.form.get("rating")
    review = request.form.get("review")
    if not rating or not rating.isdigit() or not (1 <= int(rating) <= 5):
        flash("Invalid rating. Please provide a value between 1 and 5.", "danger")
        return redirect("/customer/dashboard")
    service_request.customer_rating = float(rating)
    service_request.customer_review = review 
    db.session.commit()

    professional = service_request.professional
    if professional:
        ratings = [request.customer_rating for request in professional.professional_requests if request.customer_rating > 0]
        if ratings:
            professional_avg_rating = sum(ratings) / len(ratings)
        else:
            professional_avg_rating = 0.0
        professional.average_rating = professional_avg_rating
        db.session.commit()

    flash("Thank you for your feedback!", "success")
    return redirect("/customer/dashboard")

@app.route("/customer/search", methods=["GET", "POST"])
def search_services():
    if request.method == "GET":
        all_services = HouseholdServices.query.all()
        return render_template("customer_search.html", results='', all_services=all_services)
    if request.method == "POST":
        service_title = request.form.get("service_title")
        postal_code = request.form.get("postal_code")
        if not service_title and not postal_code:
            flash("Please enter a service or postal code to search.", "danger")
            all_services = HouseholdServices.query.all()
            return render_template("customer_search.html", results='', all_services=all_services)
        query = HouseholdServices.query
        if service_title:
            query = query.filter(HouseholdServices.service_title.ilike(f"%{service_title}%"))
        if postal_code:
            query = query.join(User, User.service_id == HouseholdServices.id) \
                         .filter(User.postal_code == postal_code)
        results = query.all()

        if not results:
            flash("No services found matching your search criteria.", "warning")
            all_services = HouseholdServices.query.all()
            return render_template("customer_search.html", results=None, all_services=all_services)
        return render_template("customer_search.html", results=results, all_services=None)



#-------------------------------------------------------------------- User Login Routes --------------------------------------------------------------------------#

@app.route("/user/login", methods=['GET', 'POST'])
def user_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.user_password, password):
            if not user.approval_status:
                flash("Your account has been flagged or not yet approved. Please contact support for assistance.", 'danger')
                return redirect("/user/login")
            session['user_id'] = user.id
            session['is_customer'] = user.customer_status
            session['is_professional'] = user.professional_status
            session['username'] = user.username
            if user.customer_status:
                flash("Login successful", 'success')
                return redirect('/customer/dashboard')
            if user.professional_status:
                if not user.service_id:
                    flash('Your selected service is not available. Please create a new account with a valid service.', 'danger')
                    return redirect('/user/login')
                flash("Login successful", 'success')
                return redirect('/professional/dashboard')

        flash("Your account has been flagged or not yet approved. Please contact support for assistance.", 'danger')

    return render_template('user_login.html')


@app.route("/logout")
def logout():
    session.pop('username',None)
    session.pop('is_customer',None)
    session.pop('is_admin',None)
    session.pop('is_professional',None)
    return redirect (url_for('hello'))




if __name__ =="__main__":
    app.run(debug=True) 