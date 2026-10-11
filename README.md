# Emergency Medical QR — Flask Web App

A prototype with three interfaces:

1. Public Emergency QR page
2. Doctor dashboard
3. Patient dashboard

It includes:
- QR code generation
- Public emergency information
- Patient/doctor login
- Patient-doctor relationship
- Mutual approval for medical-data changes
- Audit log
- PostgreSQL support for online deployment
- SQLite fallback for local development

## Demo accounts

These are fictional accounts for testing only:

- Patient: `P1001` / `Patient@123`
- Doctor: `D1001` / `Doctor@123`

Change/remove these before any real deployment.

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Online deployment

Recommended prototype architecture:

Browser -> Render Flask app -> PostgreSQL database

1. Create a PostgreSQL database.
2. Put this project in a GitHub repository.
3. Create a Render Web Service connected to that repository.
4. Build command:
   `pip install -r requirements.txt`
5. Start command:
   `gunicorn app:app`
6. Add environment variables:
   - `SECRET_KEY` = a long random value
   - `DATABASE_URL` = your PostgreSQL connection string
7. Deploy.

The app automatically uses PostgreSQL when `DATABASE_URL` is set.

## Important security limitations

This is a prototype, not a certified medical-record system.

Before real patient use, add:
- strong MFA/OTP
- verified doctor credentials
- proper consent/authorization policies
- encryption and key management
- rate limiting
- CSRF protection
- secure cookie configuration
- security headers
- database backups and recovery
- privacy/legal compliance appropriate to the country
- data retention/deletion policy
- incident logging/monitoring
- professional security review

Do not put real patient information into the demo.

## Data model

Patient -> DoctorPatient -> Doctor

Patient/Doctor -> ChangeRequest -> other party approves/rejects

All important actions -> AuditLog
