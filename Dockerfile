# Stage 1: Build the Go binary
FROM golang:1.24-alpine AS builder

# Set working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum to leverage Docker cache for dependencies
COPY go.mod go.sum ./

# Download dependencies (modules)
RUN go mod download

# Copy the rest of the source code into the container
COPY . .

# Build the application statically linked, disabling CGO (producing a standalone binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-s -w" -o server .

# Stage 2: Create a minimal production image
FROM scratch

# Copy the built binary and static files from builder stage
COPY --from=builder /app/server /server

# Expose the port your Go app listens on (change if different)
EXPOSE 8888

# Command to run the executable
ENTRYPOINT ["/server"]
