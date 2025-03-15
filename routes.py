from flask import render_template, url_for, flash, redirect, request, send_file
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import pandas as pd
import plotly.express as px
import plotly.utils
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import json
from app import app, db, bcrypt, User, Dataset, mail
from flask_mail import Message
from datetime import datetime, timedelta
import secrets

ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check email and password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    datasets = Dataset.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', datasets=datasets)

@app.route('/upload', methods=['POST'])
@login_required
def upload_dataset():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    description = request.form.get('description', '')
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        dataset = Dataset(filename=filename, description=description, user_id=current_user.id)
        db.session.add(dataset)
        db.session.commit()
        
        flash('Dataset uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    flash('Invalid file type', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/dataset/<int:dataset_id>')
@login_required
def view_dataset(dataset_id):
    dataset = Dataset.query.get_or_404(dataset_id)
    if dataset.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], dataset.filename)
    df = pd.read_csv(filepath) if dataset.filename.endswith('.csv') else pd.read_excel(filepath)
    
    # Basic statistics
    stats = {
        'rows': len(df),
        'columns': len(df.columns),
        'missing_values': df.isnull().sum().sum(),
        'numeric_columns': len(df.select_dtypes(include=[np.number]).columns),
        'categorical_columns': len(df.select_dtypes(include=['object']).columns)
    }

    # Create theme-aware layout template
    layout_template = {
        'template': 'plotly',
        'paper_bgcolor': 'rgba(0,0,0,0)',
        'plot_bgcolor': 'rgba(0,0,0,0)',
        'font': {
            'family': 'Inter, system-ui, sans-serif',
        },
        'title': {
            'font': {
                'size': 24,
                'family': 'Inter, system-ui, sans-serif',
            },
            'x': 0.5,
            'xanchor': 'center'
        },
        'margin': {'t': 50, 'b': 50, 'l': 50, 'r': 50},
        'showlegend': True,
        'legend': {
            'orientation': 'h',
            'yanchor': 'bottom',
            'y': -0.2,
            'xanchor': 'center',
            'x': 0.5
        },
        # Disable zoom and pan
        'xaxis': {
            'fixedrange': True
        },
        'yaxis': {
            'fixedrange': True
        },
        'dragmode': False,
        'selectdirection': 'any'
    }

    plots = []
    
    # Numeric columns analysis
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        # Distribution plots
        for col in numeric_cols[:3]:
            fig = px.histogram(
                df, 
                x=col,
                title=f'Distribution of {col}',
                color_discrete_sequence=['rgba(139, 92, 246, 0.7)'],
                marginal='box'
            )
            fig.update_layout(**layout_template)
            fig.update_traces(
                hovertemplate='Value: %{x}<br>Count: %{y}<extra></extra>'  # Simplified hover text
            )
            plots.append({
                'id': f'dist-{col}',
                'json': json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder),
                'title': f'Distribution Analysis: {col}'
            })

        # Correlation heatmap
        if len(numeric_cols) > 1:
            corr = df[numeric_cols].corr()
            fig = px.imshow(
                corr,
                title='Correlation Heatmap',
                color_continuous_scale='RdBu',
                aspect='auto'
            )
            fig.update_layout(**layout_template)
            fig.update_traces(
                hovertemplate='x: %{x}<br>y: %{y}<br>Correlation: %{z:.2f}<extra></extra>'
            )
            plots.append({
                'id': 'correlation',
                'json': json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder),
                'title': 'Correlation Analysis'
            })

            # Scatter matrix for first 4 numeric columns
            if len(numeric_cols) >= 2:
                fig = px.scatter_matrix(
                    df[numeric_cols[:4]],
                    title='Scatter Matrix',
                    color_discrete_sequence=['rgba(139, 92, 246, 0.7)']
                )
                fig.update_layout(**layout_template)
                plots.append({
                    'id': 'scatter-matrix',
                    'json': json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder),
                    'title': 'Scatter Matrix Analysis'
                })

    # Categorical columns analysis
    categorical_cols = df.select_dtypes(include=['object']).columns
    if len(categorical_cols) > 0:
        for col in categorical_cols[:2]:
            value_counts = df[col].value_counts()[:10]
            fig = px.bar(
                x=value_counts.index,
                y=value_counts.values,
                title=f'Top 10 Categories in {col}',
                color_discrete_sequence=['rgba(139, 92, 246, 0.7)']
            )
            fig.update_layout(**layout_template)
            plots.append({
                'id': f'cat-{col}',
                'json': json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder),
                'title': f'Category Analysis: {col}'
            })

    return render_template('dataset.html',
                         dataset=dataset,
                         stats=stats,
                         plots=plots,
                         columns=df.columns.tolist())

@app.route('/download/<int:dataset_id>')
@login_required
def download_dataset(dataset_id):
    dataset = Dataset.query.get_or_404(dataset_id)
    if dataset.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], dataset.filename)
    return send_file(filepath, as_attachment=True)

@app.route('/delete/<int:dataset_id>', methods=['POST'])
@login_required
def delete_dataset(dataset_id):
    dataset = Dataset.query.get_or_404(dataset_id)
    if dataset.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], dataset.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(dataset)
    db.session.commit()
    
    flash('Dataset deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate token
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Send email
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                        sender='your-email@gmail.com',
                        recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.

This link will expire in 1 hour.
'''
            mail.send(msg)
            
            flash('Check your email for the instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        
        flash('Email address not found.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    user = User.query.filter_by(reset_token=token).first()
    
    if user is None or user.reset_token_expiry < datetime.utcnow():
        flash('That is an invalid or expired reset token', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
        
        # Hash the new password and save
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been updated! You can now log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html') 