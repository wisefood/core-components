FROM python:3.13

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY ./requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# The MinIO client, vendored: dl.min.io answers 410 Gone since MinIO withdrew
# its community downloads. bin/mc is the open-source client (AGPLv3,
# https://github.com/minio/mc) built by bin/build-mc.sh; its checksum is in
# bin/mc.sha256.
COPY ./bin/mc /usr/local/bin/mc
RUN chmod +x /usr/local/bin/mc && mc --version

# The application itself. Only run.py: `COPY .` would put a second copy of
# bin/mc into the image.
COPY ./run.py /app/

# Set the PYTHONPATH (modify as needed)
ENV PYTHONPATH=/app/src

# Run the application
CMD ["python3", "run.py"]
