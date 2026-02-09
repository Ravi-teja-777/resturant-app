from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError
import uuid
import os
from datetime import datetime
from decimal import Decimal
import traceback
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ravi-teja-restaurant-secret-key-2024-secure'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# AWS Configuration
AWS_REGION = 'us-east-1'
BUCKET_NAME = "ravi-teja-restaurant-bucket"
USERS_TABLE = "restaurant-users"
MENU_TABLE = "restaurant-menu"
ORDERS_TABLE = "restaurant-orders"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:restaurant-notifications"  # Update with your ARN

# AWS clients
s3 = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns = boto3.client('sns', region_name=AWS_REGION)

users_table = dynamodb.Table(USERS_TABLE)
menu_table = dynamodb.Table(MENU_TABLE)
orders_table = dynamodb.Table(ORDERS_TABLE)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to protect admin routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login_page'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def send_sns_notification(subject, message, phone_number=None):
    """Send SNS notification"""
    try:
        # Publish to topic for email subscribers
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        
        # Send SMS if phone number provided
        if phone_number:
            # Format phone number to E.164 format (+919876543210)
            if not phone_number.startswith('+'):
                phone_number = '+91' + phone_number  # Assuming Indian numbers
            
            sns.publish(
                PhoneNumber=phone_number,
                Message=message[:140]  # SMS character limit
            )
        
        print(f"[SNS] Notification sent: {subject}")
    except Exception as e:
        print(f"[SNS] Error sending notification: {str(e)}")

def init_aws_resources():
    """Initialize all AWS resources"""
    print("\n" + "="*60)
    print("Initializing AWS Resources for Ravi Teja's Restaurant...")
    print("="*60)
    
    try:
        # 1. Create S3 bucket
        try:
            s3.head_bucket(Bucket=BUCKET_NAME)
            print(f"✓ S3 bucket '{BUCKET_NAME}' exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                try:
                    if AWS_REGION == 'us-east-1':
                        s3.create_bucket(Bucket=BUCKET_NAME)
                    else:
                        s3.create_bucket(
                            Bucket=BUCKET_NAME,
                            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
                        )
                    
                    # Set bucket to public-read for images
                    s3.put_public_access_block(
                        Bucket=BUCKET_NAME,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': False,
                            'IgnorePublicAcls': False,
                            'BlockPublicPolicy': False,
                            'RestrictPublicBuckets': False
                        }
                    )
                    
                    print(f"✓ Created S3 bucket '{BUCKET_NAME}'")
                except ClientError as create_error:
                    print(f"✗ Failed to create S3 bucket: {str(create_error)}")
        
        # 2. Check DynamoDB tables
        tables_info = {
            USERS_TABLE: "username (String)",
            MENU_TABLE: "item_id (String)",
            ORDERS_TABLE: "order_id (String)"
        }
        
        for table_name, pk_info in tables_info.items():
            try:
                table = dynamodb.Table(table_name)
                table.load()
                print(f"✓ DynamoDB table '{table_name}' exists")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print(f"✗ DynamoDB table '{table_name}' does NOT exist")
                    print(f"   Please create it with Partition key: {pk_info}")
        
        print("="*60)
        print("AWS Resource Initialization Complete")
        print("="*60 + "\n")
            
    except Exception as e:
        print(f"\n✗ AWS initialization error: {str(e)}")
        print(traceback.format_exc())

# ==================== PUBLIC PAGES ====================

@app.route('/')
def home():
    """Home page - Landing page"""
    return render_template('home.html')

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@app.route('/menu')
def menu_page():
    """Public menu page - anyone can view"""
    try:
        # Get all menu items
        response = menu_table.scan()
        menu_items = response.get('Items', [])
        
        # Sort by category and name
        menu_items.sort(key=lambda x: (x.get('category', 'Other'), x.get('name', '')))
        
        return render_template('menu.html', menu_items=menu_items)
    except Exception as e:
        flash(f'Error loading menu: {str(e)}', 'error')
        return render_template('menu.html', menu_items=[])

# ==================== AUTH PAGES ====================

@app.route('/signup')
def signup_page():
    """Signup page"""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('signup.html')

@app.route('/login')
def login_page():
    """Login page"""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('login.html')

# ==================== USER DASHBOARD ====================

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    """User dashboard - View menu and order"""
    try:
        # Get all menu items
        response = menu_table.scan()
        menu_items = response.get('Items', [])
        
        # Filter only available items
        menu_items = [item for item in menu_items if item.get('available', True)]
        menu_items.sort(key=lambda x: (x.get('category', 'Other'), x.get('name', '')))
        
        # Get user's recent orders
        user_orders = orders_table.scan(
            FilterExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': session['user_id']},
            Limit=10
        )
        
        orders = sorted(
            user_orders.get('Items', []),
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )
        
        return render_template('user_dashboard.html', 
                             menu_items=menu_items,
                             orders=orders,
                             username=session.get('username'))
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('user_dashboard.html', menu_items=[], orders=[])

@app.route('/user/orders')
@login_required
def user_orders():
    """User orders page - View order history"""
    try:
        response = orders_table.scan(
            FilterExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': session['user_id']}
        )
        
        orders = sorted(
            response.get('Items', []),
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )
        
        return render_template('user_orders.html', orders=orders)
    except Exception as e:
        flash(f'Error loading orders: {str(e)}', 'error')
        return render_template('user_orders.html', orders=[])

# ==================== ADMIN DASHBOARD ====================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - Overview"""
    try:
        # Get all orders
        orders_response = orders_table.scan()
        all_orders = orders_response.get('Items', [])
        
        # Get pending orders
        pending_orders = [o for o in all_orders if o.get('status') == 'pending']
        
        # Get all menu items
        menu_response = menu_table.scan()
        menu_items = menu_response.get('Items', [])
        
        # Get all users
        users_response = users_table.scan()
        all_users = users_response.get('Items', [])
        
        # Calculate statistics
        stats = {
            'total_orders': len(all_orders),
            'pending_orders': len(pending_orders),
            'total_menu_items': len(menu_items),
            'total_users': len(all_users),
            'accepted_orders': len([o for o in all_orders if o.get('status') == 'accepted']),
            'rejected_orders': len([o for o in all_orders if o.get('status') == 'rejected'])
        }
        
        # Sort pending orders by date (newest first)
        pending_orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template('admin_dashboard.html', 
                             stats=stats,
                             pending_orders=pending_orders[:10])
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('admin_dashboard.html', stats={}, pending_orders=[])

@app.route('/admin/orders')
@admin_required
def admin_orders():
    """Admin orders page - Manage all orders"""
    try:
        response = orders_table.scan()
        orders = sorted(
            response.get('Items', []),
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )
        
        return render_template('admin_orders.html', orders=orders)
    except Exception as e:
        flash(f'Error loading orders: {str(e)}', 'error')
        return render_template('admin_orders.html', orders=[])

@app.route('/admin/menu')
@admin_required
def admin_menu():
    """Admin menu page - Manage menu items"""
    try:
        response = menu_table.scan()
        menu_items = sorted(
            response.get('Items', []),
            key=lambda x: (x.get('category', 'Other'), x.get('name', ''))
        )
        
        return render_template('admin_menu.html', menu_items=menu_items)
    except Exception as e:
        flash(f'Error loading menu: {str(e)}', 'error')
        return render_template('admin_menu.html', menu_items=[])

# ==================== API ROUTES - AUTH ====================

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """API: User signup"""
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'password', 'phone']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'{field} is required'}), 400
        
        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        phone = data['phone'].strip()
        password = data['password']
        role = data.get('role', 'user')  # Default to 'user' if not provided
        
        # Validate role
        if role not in ['user', 'admin']:
            return jsonify({'error': 'Invalid role. Must be user or admin'}), 400
        
        # Check if user exists
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Check email uniqueness
        email_check = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if email_check.get('Items'):
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        
        users_table.put_item(
            Item={
                'username': username,
                'user_id': user_id,
                'email': email,
                'phone': phone,
                'password': hashed_password,
                'role': role,
                'created_at': datetime.now().isoformat()
            }
        )
        
        # Send welcome notification
        send_sns_notification(
            subject="Welcome to Ravi Teja's Restaurant!",
            message=f"Hello {username}! Welcome to our restaurant. Start ordering delicious food now!",
            phone_number=phone
        )
        
        return jsonify({
            'success': True,
            'message': 'Signup successful! Please login.',
            'redirect': url_for('login_page')
        }), 201
        
    except Exception as e:
        print(f"[SIGNUP] Error: {str(e)}")
        return jsonify({'error': f'Signup failed: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """API: User login"""
    try:
        data = request.get_json()
        
        if 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username'].strip().lower()
        password = data['password']
        
        # Get user
        response = users_table.get_item(Key={'username': username})
        
        if 'Item' not in response:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        user = response['Item']
        
        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Set session
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['role'] = user.get('role', 'user')
        
        # Determine redirect based on role
        if user.get('role') == 'admin':
            redirect_url = url_for('admin_dashboard')
        else:
            redirect_url = url_for('user_dashboard')
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'role': user.get('role', 'user'),
            'redirect': redirect_url
        }), 200
        
    except Exception as e:
        print(f"[LOGIN] Error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    """API: Logout"""
    session.clear()
    
    if request.method == 'GET':
        flash('You have been logged out', 'success')
        return redirect(url_for('home'))
    
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ==================== API ROUTES - MENU ====================

@app.route('/api/menu/add', methods=['POST'])
@admin_required
def api_add_menu_item():
    """API: Add new menu item"""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'Image is required'}), 400
        
        file = request.files['image']
        name = request.form.get('name', '').strip()
        price = request.form.get('price', '').strip()
        category = request.form.get('category', 'Other').strip()
        dish_type = request.form.get('dish_type', 'veg').strip()
        description = request.form.get('description', '').strip()
        
        if not name or not price:
            return jsonify({'error': 'Name and price are required'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use PNG, JPG, JPEG, or WEBP'}), 400
        
        # Upload image to S3
        item_id = str(uuid.uuid4())
        filename = f"menu/{item_id}/{secure_filename(file.filename)}"
        
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=filename,
            Body=file.read(),
            ContentType=file.content_type,
            ACL='public-read'
        )
        
        # Get image URL
        image_url = f"https://{BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{filename}"
        
        # Save to DynamoDB
        menu_table.put_item(
            Item={
                'item_id': item_id,
                'name': name,
                'price': Decimal(str(price)),
                'category': category,
                'dish_type': dish_type,
                'description': description,
                'image_url': image_url,
                's3_key': filename,
                'available': True,
                'created_at': datetime.now().isoformat(),
                'created_by': session['username']
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'Menu item added successfully',
            'item_id': item_id
        }), 201
        
    except Exception as e:
        print(f"[ADD MENU] Error: {str(e)}")
        return jsonify({'error': f'Failed to add menu item: {str(e)}'}), 500

@app.route('/api/menu/update/<item_id>', methods=['POST'])
@admin_required
def api_update_menu_item(item_id):
    """API: Update menu item"""
    try:
        # Get existing item
        response = menu_table.get_item(Key={'item_id': item_id})
        if 'Item' not in response:
            return jsonify({'error': 'Menu item not found'}), 404
        
        existing_item = response['Item']
        
        # Update fields
        name = request.form.get('name', existing_item['name']).strip()
        price = request.form.get('price', str(existing_item['price'])).strip()
        category = request.form.get('category', existing_item.get('category', 'Other')).strip()
        dish_type = request.form.get('dish_type', existing_item.get('dish_type', 'veg')).strip()
        description = request.form.get('description', existing_item.get('description', '')).strip()
        available = request.form.get('available', 'true').lower() == 'true'
        
        update_data = {
            'name': name,
            'price': Decimal(str(price)),
            'category': category,
            'dish_type': dish_type,
            'description': description,
            'available': available,
            'updated_at': datetime.now().isoformat()
        }
        
        # Handle image update
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if allowed_file(file.filename):
                # Delete old image
                if 's3_key' in existing_item:
                    try:
                        s3.delete_object(Bucket=BUCKET_NAME, Key=existing_item['s3_key'])
                    except:
                        pass
                
                # Upload new image
                filename = f"menu/{item_id}/{secure_filename(file.filename)}"
                s3.put_object(
                    Bucket=BUCKET_NAME,
                    Key=filename,
                    Body=file.read(),
                    ContentType=file.content_type,
                    ACL='public-read'
                )
                
                image_url = f"https://{BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{filename}"
                update_data['image_url'] = image_url
                update_data['s3_key'] = filename
        
        # Update in DynamoDB
        update_expression = "SET " + ", ".join([f"{k} = :{k}" for k in update_data.keys()])
        expression_values = {f":{k}": v for k, v in update_data.items()}
        
        menu_table.update_item(
            Key={'item_id': item_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        return jsonify({
            'success': True,
            'message': 'Menu item updated successfully'
        }), 200
        
    except Exception as e:
        print(f"[UPDATE MENU] Error: {str(e)}")
        return jsonify({'error': f'Failed to update menu item: {str(e)}'}), 500

@app.route('/api/menu/delete/<item_id>', methods=['DELETE'])
@admin_required
def api_delete_menu_item(item_id):
    """API: Delete menu item"""
    try:
        # Get item
        response = menu_table.get_item(Key={'item_id': item_id})
        if 'Item' not in response:
            return jsonify({'error': 'Menu item not found'}), 404
        
        item = response['Item']
        
        # Delete image from S3
        if 's3_key' in item:
            try:
                s3.delete_object(Bucket=BUCKET_NAME, Key=item['s3_key'])
            except Exception as e:
                print(f"Error deleting S3 object: {str(e)}")
        
        # Delete from DynamoDB
        menu_table.delete_item(Key={'item_id': item_id})
        
        return jsonify({
            'success': True,
            'message': 'Menu item deleted successfully'
        }), 200
        
    except Exception as e:
        print(f"[DELETE MENU] Error: {str(e)}")
        return jsonify({'error': f'Failed to delete menu item: {str(e)}'}), 500

@app.route('/api/menu/toggle/<item_id>', methods=['POST'])
@admin_required
def api_toggle_menu_availability(item_id):
    """API: Toggle menu item availability"""
    try:
        response = menu_table.get_item(Key={'item_id': item_id})
        if 'Item' not in response:
            return jsonify({'error': 'Menu item not found'}), 404
        
        current_status = response['Item'].get('available', True)
        new_status = not current_status
        
        menu_table.update_item(
            Key={'item_id': item_id},
            UpdateExpression='SET available = :status',
            ExpressionAttributeValues={':status': new_status}
        )
        
        return jsonify({
            'success': True,
            'message': f'Item is now {"available" if new_status else "unavailable"}',
            'available': new_status
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== API ROUTES - ORDERS ====================

@app.route('/api/order/create', methods=['POST'])
@login_required
def api_create_order():
    """API: Create new order"""
    try:
        data = request.get_json()
        
        required_fields = ['item_id', 'name', 'phone', 'location']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'{field} is required'}), 400
        
        item_id = data['item_id']
        customer_name = data['name'].strip()
        customer_phone = data['phone'].strip()
        location = data['location'].strip()
        quantity = int(data.get('quantity', 1))
        special_instructions = data.get('special_instructions', '').strip()
        
        # Get menu item
        menu_response = menu_table.get_item(Key={'item_id': item_id})
        if 'Item' not in menu_response:
            return jsonify({'error': 'Menu item not found'}), 404
        
        menu_item = menu_response['Item']
        
        if not menu_item.get('available', True):
            return jsonify({'error': 'This item is currently unavailable'}), 400
        
        # Calculate total
        item_price = float(menu_item['price'])
        total_price = item_price * quantity
        
        # Create order
        order_id = str(uuid.uuid4())
        
        orders_table.put_item(
            Item={
                'order_id': order_id,
                'user_id': session['user_id'],
                'username': session['username'],
                'item_id': item_id,
                'item_name': menu_item['name'],
                'item_price': Decimal(str(item_price)),
                'quantity': quantity,
                'total_price': Decimal(str(total_price)),
                'customer_name': customer_name,
                'customer_phone': customer_phone,
                'location': location,
                'special_instructions': special_instructions,
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        )
        
        # Send notification to admin (via SNS topic)
        send_sns_notification(
            subject="New Order Received!",
            message=f"New order #{order_id[:8]} from {customer_name}\nItem: {menu_item['name']} x{quantity}\nTotal: ₹{total_price}\nLocation: {location}"
        )
        
        # Send confirmation to customer
        send_sns_notification(
            subject="Order Placed Successfully",
            message=f"Your order for {menu_item['name']} has been placed. We'll contact you soon!",
            phone_number=customer_phone
        )
        
        return jsonify({
            'success': True,
            'message': 'Order placed successfully! We will contact you soon.',
            'order_id': order_id
        }), 201
        
    except Exception as e:
        print(f"[CREATE ORDER] Error: {str(e)}")
        return jsonify({'error': f'Failed to create order: {str(e)}'}), 500

@app.route('/api/order/update/<order_id>', methods=['POST'])
@admin_required
def api_update_order_status(order_id):
    """API: Update order status (accept/reject)"""
    try:
        data = request.get_json()
        
        if 'status' not in data:
            return jsonify({'error': 'Status is required'}), 400
        
        status = data['status']
        if status not in ['accepted', 'rejected', 'completed']:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Get order
        response = orders_table.get_item(Key={'order_id': order_id})
        if 'Item' not in response:
            return jsonify({'error': 'Order not found'}), 404
        
        order = response['Item']
        
        # Update order
        orders_table.update_item(
            Key={'order_id': order_id},
            UpdateExpression='SET #status = :status, updated_at = :updated_at, updated_by = :admin',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': status,
                ':updated_at': datetime.now().isoformat(),
                ':admin': session['username']
            }
        )
        
        # Send notification to customer
        if status == 'accepted':
            message = f"Great news! Your order for {order['item_name']} has been accepted. We're preparing it now!"
        elif status == 'rejected':
            message = f"Sorry, we couldn't accept your order for {order['item_name']} at this time. Please contact us for details."
        else:
            message = f"Your order for {order['item_name']} has been completed. Thank you for choosing us!"
        
        send_sns_notification(
            subject=f"Order {status.title()}",
            message=message,
            phone_number=order.get('customer_phone')
        )
        
        return jsonify({
            'success': True,
            'message': f'Order {status} successfully'
        }), 200
        
    except Exception as e:
        print(f"[UPDATE ORDER] Error: {str(e)}")
        return jsonify({'error': f'Failed to update order: {str(e)}'}), 500

@app.route('/api/order/delete/<order_id>', methods=['DELETE'])
@admin_required
def api_delete_order(order_id):
    """API: Delete order"""
    try:
        orders_table.delete_item(Key={'order_id': order_id})
        
        return jsonify({
            'success': True,
            'message': 'Order deleted successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== API ROUTES - CONTACT ====================

@app.route('/api/contact', methods=['POST'])
def api_contact():
    """API: Contact form submission"""
    try:
        data = request.get_json()
        
        required_fields = ['name', 'email', 'message']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'{field} is required'}), 400
        
        name = data['name'].strip()
        email = data['email'].strip()
        phone = data.get('phone', '').strip()
        message = data['message'].strip()
        
        # Send notification to admin
        contact_message = f"New Contact Form Submission\n\nName: {name}\nEmail: {email}\nPhone: {phone}\n\nMessage:\n{message}"
        
        send_sns_notification(
            subject="New Contact Form Message",
            message=contact_message
        )
        
        return jsonify({
            'success': True,
            'message': 'Thank you for contacting us! We will get back to you soon.'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize AWS resources on startup
    init_aws_resources()
    
    print("\n" + "="*60)
    print("🍽️  RAVI TEJA'S RESTAURANT - SERVER STARTING")
    print("="*60)
    print(f"Server available at: http://0.0.0.0:5000")
    print("Press CTRL+C to quit")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
