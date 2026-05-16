# Use Python 3.11 slim as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
# We copy the root directory but only need backend/ and analyzer.py (if imported)
# Actually, looking at main.py, it doesn't seem to import analyzer.py but uses sslyze.
COPY . .

# Expose port 8000
EXPOSE 8000

# Command to run the application
# Using uvicorn with host 0.0.0.0 to allow external connections
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
