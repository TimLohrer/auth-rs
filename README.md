# Auth-RS

A Rust-based authentication system with a SvelteKit frontend.

## Docker Setup

This project uses Docker and Docker Compose to run the entire application stack, including:
- MongoDB database
- Rust backend
- SvelteKit frontend

### Prerequisites

- Docker and Docker Compose installed on your system
- Git (to clone the repository)

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/alex1607/auth-rs.git
   cd auth-rs
   ```

2. Configure environment variables (optional):
   - The default configuration is in the `.env` file
   - You can modify these values as needed

3. Build the Docker images in the root folder and in the `backend` folder:
   ```bash
   docker-compose build
   ```

4. Start the application:
   ```bash
   docker-compose up -d
   ```

5. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000

6. Default admin credentials:
   - Email: admin@example.com
   - Password: admin

### Stopping the Application

```bash
docker-compose down
```

To remove all data (including the MongoDB volume):
```bash
docker-compose down -v
```

## Development

For local development without Docker:

### Backend

```bash
cd backend
cargo run
```

### Frontend

```bash
bun install
bun run dev
```

## License

Icons: <https://lucide.dev/license>
