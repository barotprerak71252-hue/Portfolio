# Portfolio — full stack (Node/Express + MongoDB)

One service serves everything: the portfolio (`/`), the API (`/api/*`) and the admin panel (`/admin`).
Visitors' messages are saved in MongoDB. Only you (password login) can read messages and add/edit/delete projects.

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env` and fill it in (steps below).
3. `npm start` → open http://localhost:3000 and http://localhost:3000/admin

## Go live (free)
1. **Database:** create a free cluster on MongoDB Atlas → Database Access: add a user → Network Access: allow `0.0.0.0/0` → Connect → Drivers → copy the URI into `MONGODB_URI` (put `/portfolio` before the `?`).
2. **Secrets:** `JWT_SECRET` = output of `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. `ADMIN_PASSWORD` = a long password only you know.
3. **GitHub:** push this folder to a new repo (`.env` is git-ignored — never commit it).
4. **Render:** New → Web Service → connect the repo. Build command `npm install`, start command `npm start`. Add the three environment variables. Deploy.
5. Open `https://<your-service>.onrender.com/admin`, log in, and edit the three starter projects (add their repo/live URLs).

Notes: Render's free tier sleeps when idle, so the first visit can take ~50 seconds. Add your own domain later in Render's settings.
