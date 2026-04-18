# CSRF Scanner - Render Deployment Guide

## 🚀 Deploy to Render

### Prerequisites
- A [Render](https://render.com) account
- Your project pushed to GitHub

### Deployment Steps

1. **Connect your GitHub repository to Render:**
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New" → "Web Service"
   - Connect your GitHub repository

2. **Configure the service:**
   - **Name:** `csrf-scanner` (or your preferred name)
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python api_server.py`

3. **Environment Variables:**
   The following environment variables will be automatically set by Render:
   - `PORT` - The port your app should listen on
   - `FLASK_ENV=production`
   - `SECRET_KEY` - Auto-generated
   - `JWT_SECRET_KEY` - Auto-generated
   - `PYTHONUNBUFFERED=1`

4. **Deploy:**
   - Click "Create Web Service"
   - Render will build and deploy your application
   - Your app will be available at `https://your-service-name.onrender.com`

### Accessing Your Application

- **Dashboard:** `https://your-service-name.onrender.com`
- **API:** `https://your-service-name.onrender.com/api/v1/`
- **Health Check:** `https://your-service-name.onrender.com/api/v1/health`

### Default Login Credentials
- **Username:** `admin`
- **Password:** `admin123!`

⚠️ **Important:** Change the default password immediately after first login!

### Troubleshooting

1. **Application not starting:**
   - Check the logs in Render dashboard
   - Ensure all dependencies are in `requirements.txt`
   - Verify the `api_server.py` file is correctly configured

2. **Port issues:**
   - The app automatically uses the `PORT` environment variable set by Render
   - Do not hardcode ports in your application

3. **Static files:**
   - Templates are served from the `templates/` directory
   - Ensure all template files are included in your repository

### Production Considerations

- **Database:** Currently uses file-based storage. Consider using a database service for production
- **File Storage:** Scan results are stored locally. Consider cloud storage for persistence
- **Security:** Change default credentials and use strong secrets
- **Scaling:** Monitor resource usage and consider upgrading plans as needed

### Updating Your Deployment

To update your deployed application:
1. Push changes to your GitHub repository
2. Render will automatically rebuild and redeploy
3. Or manually trigger a deploy from the Render dashboard

### Support

If you encounter issues:
- Check Render's [Python documentation](https://docs.render.com/deploy-python)
- Review application logs in the Render dashboard
- Ensure your `requirements.txt` includes all necessary dependencies