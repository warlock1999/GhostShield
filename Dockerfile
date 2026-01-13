# Use ultra-lightweight Python Alpine
FROM python:3.11-alpine

WORKDIR /app

# Install high-performance async library
RUN pip install --no-cache-dir aiohttp

# Copy script
COPY ghost_doh.py .

# Create non-root user for security
RUN adduser -D ghost
USER ghost

# Expose port
EXPOSE 8443

# Run
CMD ["python", "ghost_doh.py"]
