# EventSphere (C++ / SQLite / vanilla JS)

## Build and run (Ubuntu/WSL; on Windows use WSL or MSYS2 with the same packages)
    sudo apt install g++ cmake libsqlite3-dev libssl-dev curl
    ./setup.sh                      # downloads cpp-httplib + nlohmann/json headers
    cmake -S backend -B build && cmake --build build
    ADMIN_EMAIL=admin@college.edu ADMIN_PASSWORD=ChangeMe123 ./build/eventsphere
Open http://localhost:8080 (run from the project root; the server also serves the frontend).
The admin is created at startup from the env vars (dev only; use your own password, never commit it).

## Implemented
Signup/login/logout (PBKDF2-SHA256 salted hashes, HttpOnly session cookie), role checks on the server,
event proposals -> admin approve / reject / request changes (with history), organizer edit + re-review,
public listing of published events only, search + category filter, registration with unique ID,
duplicate prevention, closed/full checks, atomic capacity (BEGIN IMMEDIATE transaction), cancellation,
My Registrations, admin stats and category chart from real DB data.

## Not yet implemented (next stages)
Waiting list, QR codes + scanner, PDF certificates + verification page, SMTP email delivery,
CSV export, rate limiting, automated tests, user management and profile pages.
