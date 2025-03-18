FROM python:3.7-alpine AS builder
RUN apk --update add bash nano g++ \
    && adduser -D -u 1000 vampiuser  # Create a non-root user

# Copy application files and install dependencies
COPY . /vampi
WORKDIR /vampi
RUN pip install -r requirements.txt

# Build a fresh container, copying across files & compiled parts
FROM python:3.7-alpine
RUN apk --update add bash \
    && adduser -D -u 1000 vampiuser  # Create the same non-root user in the final image

# Copy application files and compiled dependencies
COPY . /vampi
WORKDIR /vampi
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin

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
