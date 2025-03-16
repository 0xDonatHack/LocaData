# Data Analytics Platform

A secure and beautiful web application for data analysis and visualization built with Flask.

## Features

- User Authentication & Authorization
- Secure File Upload & Management
- Data Analysis & Visualization
- Admin Panel
- Beautiful Modern UI with Tailwind CSS
- Interactive Charts with Plotly
- Secure Password Handling
- File Type Validation
- Responsive Design

## Setup Instructions

1. Clone the repository:
```bash
git clone <repository-url>
cd loginAuth
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory:
```
SECRET_KEY=your-secret-key-here
```

5. Create necessary directories:
```bash
mkdir uploads
mkdir templates
```

6. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Supported File Types

- CSV (.csv)
- Excel (.xlsx, .xls)

## Security Features

- Password Hashing with Bcrypt
- CSRF Protection
- Secure File Upload
- User Authentication
- Admin Authorization
- Input Validation
- Secure Session Management

## Directory Structure

```
loginAuth/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── uploads/           # Upload directory for datasets
└── templates/         # HTML templates
    ├── base.html
    ├── home.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    └── dataset.html
```

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

MIT License

## Email Configuration

This application uses Gmail for sending password reset emails. To set this up:

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Set up Gmail App Password:
   - Go to your Google Account settings
   - Enable 2-Step Verification
   - Go to Security → App passwords
   - Generate a new app password for the application
   - Update the `MAIL_PASSWORD` in `.env` with this password

3. Update other environment variables in `.env`:
   - Set `MAIL_USERNAME` to your Gmail address
   - Set a secure `SECRET_KEY` 
