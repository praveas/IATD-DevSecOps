FROM python:3.7-alpine AS builder
RUN apk --update add bash nano g++ \
    && adduser -D -u 1000 vampiuser  # Create a non-root user

# Copy only necessary files
WORKDIR /vampi
COPY requirements.txt /vampi/requirements.txt
RUN pip install -r requirements.txt

# Build a fresh container, copying across files & compiled parts
FROM python:3.7-alpine
RUN apk --update add bash \
    && adduser -D -u 1000 vampiuser  # Create the same non-root user in the final image

# Copy only necessary files and compiled dependencies
WORKDIR /vampi
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
COPY app.py /vampi/app.py
COPY config.py /vampi/config.py
COPY constants.py /vampi/constants.py
COPY api_tests.py /vampi/api_tests.py
COPY api_views /vampi/api_views
COPY models /vampi/models
COPY openapi_specs /vampi/openapi_specs
COPY database /vampi/database

RUN chown -R vampiuser:vampiuser /vampi

# Set environment variables
ENV vulnerable=1
ENV tokentimetolive=60

# Change to the non-root user
USER vampiuser

# Expose the application port
EXPOSE 5000

# Set the entrypoint and command
ENTRYPOINT ["python"]
CMD ["app.py"]
