# Use a lightweight Python base image
FROM python:3.9-slim

# Install system dependencies required for monitoring and media parsing
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping ffmpeg sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
# ADDED: ImageHash and Pillow for perceptual video freeze detection
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==21.2.0 ImageHash Pillow

# Copy the rest of your application code into the container
COPY . .

# Sanitize the startup script and make it executable
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

# Expose the port the web GUI will run on
EXPOSE 5000

# Boot the container using our custom startup script
CMD ["./start.sh"]
