# Use official lightweight Python image
FROM python:3.11-slim

# Install system dependencies needed for network sniffing and psutil
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose web dashboard port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Run Flask application
CMD ["python", "app.py"]
