# Use a Python base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy your requirements file
COPY requirements.txt .

# Install dependencies (This is where psutil gets installed)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Set the environment variable for the port (Render requirement)
ENV PORT=10000

# Start the application
CMD ["python", "monitoring.py"]