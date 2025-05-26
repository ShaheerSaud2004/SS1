# ScarletSniper - Rutgers Course Registration Bot

## Deployment Instructions

### Prerequisites
- Python 3.8 or higher
- Redis server
- Chrome/Chromium browser
- Virtual environment (recommended)

### Server Setup

1. **Install System Dependencies**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv redis-server chromium-browser

# CentOS/RHEL
sudo yum update
sudo yum install -y python3-pip python3-venv redis chromium
```

2. **Clone and Setup Project**
```bash
git clone <your-repository-url>
cd CourseSniperOGW
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Environment Configuration**
Create a `.env` file in the project root with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///users.db
REDIS_URL=redis://localhost:6379/0
```

4. **Database Setup**
```bash
# Initialize the database
flask db init
flask db migrate
flask db upgrade
```

5. **Running with Gunicorn**
```bash
gunicorn --worker-class eventlet -w 1 app:app
```

### Production Considerations

1. **Process Management**
   - Use systemd or supervisor to manage the application process
   - Example systemd service file (`/etc/systemd/system/scarletsniper.service`):
   ```ini
   [Unit]
   Description=ScarletSniper Web Application
   After=network.target

   [Service]
   User=your-user
   WorkingDirectory=/path/to/CourseSniperOGW
   Environment="PATH=/path/to/CourseSniperOGW/venv/bin"
   ExecStart=/path/to/CourseSniperOGW/venv/bin/gunicorn --worker-class eventlet -w 1 app:app
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

2. **Nginx Configuration**
   Example Nginx configuration:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

3. **Security Considerations**
   - Enable HTTPS using Let's Encrypt
   - Set up proper firewall rules
   - Keep all dependencies updated
   - Use strong secret keys
   - Implement rate limiting

### Monitoring and Maintenance

1. **Logs**
   - Application logs are stored in the `logs/` directory
   - Monitor system logs for errors
   - Set up log rotation

2. **Backup**
   - Regularly backup the SQLite database
   - Backup environment configuration
   - Implement automated backup scripts

3. **Updates**
   - Regularly update dependencies
   - Monitor for security patches
   - Test updates in staging environment

### Troubleshooting

1. **Common Issues**
   - If Redis connection fails, check Redis service status
   - If Chrome/Selenium fails, ensure Chrome is installed and up to date
   - Check application logs for detailed error messages

2. **Performance Issues**
   - Monitor system resources
   - Check Redis memory usage
   - Optimize database queries
   - Consider scaling worker processes if needed

For additional support or questions, please contact the development team. # ScarletSnipes
