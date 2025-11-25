FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install required packages
RUN pip install boto3

# Copy the main ECS script
COPY automation/ecs_map_tagger.py /app/

# Copy all service modules
COPY modules/ /app/modules/

# Set the entrypoint
ENTRYPOINT ["python", "ecs_map_tagger.py"]