const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");

// ======== CONFIG =========
const app = express();
const PORT = process.env.PORT || 3000; // deployment-friendly
const JWT_SECRET = "my-very-long-random-secret-key-1234567890"; // <-- change this in production

// ======== MIDDLEWARE =========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use("/public", express.static(path.join(__dirname, "public")));
// Serve the same SPA for / and /admin – front-end will decide what to show
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ======== DB SETUP =========
const dbFile = path.join(__dirname, "fajr40.db");
const db = new sqlite3.Database(dbFile);

// Create tables / columns if not exist
db.serialize(() => {
  // For new databases, this is the full structure
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,             -- Child name
      parentName TEXT,                -- Parent name
      email TEXT UNIQUE NOT NULL,
      passwordHash TEXT NOT NULL,
      masjid TEXT,
      city TEXT,
      age INTEGER,
      isAdmin INTEGER DEFAULT 0,
      photoFilename TEXT,
      currentStreak INTEGER DEFAULT 0,
      bestStreak INTEGER DEFAULT 0,
      completionsCount INTEGER DEFAULT 0,
      lastCheckinDate TEXT,
      createdAt TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS checkins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      date TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (userId) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS checkin_photos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      date TEXT NOT NULL,
      photoFilename TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (userId) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sponsors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      businessName TEXT NOT NULL,
      contactEmail TEXT,
      contactPhone TEXT,
      prizeDescription TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      approved INTEGER DEFAULT 0
    )
  `);

  // For existing DBs: add missing columns safely (ignore "duplicate column" errors)
  db.run(`ALTER TABLE users ADD COLUMN age INTEGER`, (err) => {
    if (err && !String(err).includes("duplicate column")) {
      console.error("Error adding age column:", err);
    }
  });

  db.run(`ALTER TABLE users ADD COLUMN parentName TEXT`, (err) => {
    if (err && !String(err).includes("duplicate column")) {
      console.error("Error adding parentName column:", err);
    }
  });

  db.run(`ALTER TABLE users ADD COLUMN city TEXT`, (err) => {
    if (err && !String(err).includes("duplicate column")) {
      console.error("Error adding city column:", err);
    }
  });
});

// ======== UPLOAD SETUP =========
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + ext);
  },
});

const upload = multer({ storage });

// ======== AUTH HELPERS =========
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Invalid token format" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = user; // { id, email, isAdmin }
    next();
  });
}

function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

// Helper to get today's date in YYYY-MM-DD
function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

// ======== ROUTES =========

// Serve frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---- Auth: Register ----
// Fields: parentName, childName, email, password, masjid, city, age (all required)
app.post("/api/register", (req, res) => {
  let { parentName, childName, email, password, masjid, city, age } = req.body;

  if (!parentName || !childName || !email || !password || !masjid || !city || age === undefined || age === null || age === "") {
    return res.status(400).json({ error: "All fields are required (Parent, Child, Email, Password, Masjid, City, Age)" });
  }

  // Age must be between 3 and 17
  const parsedAge = parseInt(age, 10);
  if (isNaN(parsedAge) || parsedAge < 3 || parsedAge > 17) {
    return res.status(400).json({ error: "Age must be between 3 and 17 years" });
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  const stmt = db.prepare(
    "INSERT INTO users (name, parentName, email, passwordHash, masjid, city, age) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  stmt.run(
    childName.trim(),
    parentName.trim(),
    email.toLowerCase().trim(),
    passwordHash,
    masjid.trim(),
    city.trim(),
    parsedAge,
    function (err) {
      if (err) {
        console.error(err);
        return res.status(400).json({ error: "Email already registered" });
      }
      return res.json({ success: true });
    }
  );
});

// ---- Auth: Login ----
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email.toLowerCase()],
    (err, user) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!user) return res.status(400).json({ error: "Invalid credentials" });

      const valid = bcrypt.compareSync(password, user.passwordHash);
      if (!valid) return res.status(400).json({ error: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email, isAdmin: !!user.isAdmin },
        JWT_SECRET,
        { expiresIn: "7d" }
      );
      res.json({
        token,
        user: {
          id: user.id,
          name: user.name,          // Child name
          email: user.email,
          masjid: user.masjid,
          city: user.city,
          isAdmin: !!user.isAdmin,
        },
      });
    }
  );
});

// ---- Get my profile & stats ----
app.get("/api/me", authMiddleware, (req, res) => {
  db.get(
    "SELECT id, name, parentName, email, masjid, city, isAdmin, photoFilename, currentStreak, bestStreak, completionsCount, lastCheckinDate, age FROM users WHERE id = ?",
    [req.user.id],
    (err, user) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    }
  );
});

// ---- Original check-in (no photo) kept for compatibility ----
app.post("/api/checkin", authMiddleware, (req, res) => {
  const today = todayISO();

  db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.lastCheckinDate === today) {
      return res.json({
        message: "Already checked in for today",
        currentStreak: user.currentStreak,
      });
    }

    let currentStreak = user.currentStreak || 0;
    let bestStreak = user.bestStreak || 0;
    let completionsCount = user.completionsCount || 0;

    if (!user.lastCheckinDate) {
      currentStreak = 1;
    } else {
      const last = new Date(user.lastCheckinDate);
      const todayDate = new Date(today);
      const diffDays = (todayDate - last) / (1000 * 60 * 60 * 24);

      if (diffDays === 1) {
        currentStreak += 1;
      } else if (diffDays > 1) {
        currentStreak = 1;
      } else if (diffDays < 0) {
        return res
          .status(400)
          .json({ error: "System date issue: check your device clock." });
      }
    }

    if (currentStreak === 40) {
      completionsCount += 1;
    }

    if (currentStreak > bestStreak) bestStreak = currentStreak;

    db.run(
      "INSERT INTO checkins (userId, date) VALUES (?, ?)",
      [user.id, today],
      function (err2) {
        if (err2) return res.status(500).json({ error: "DB error inserting checkin" });

        db.run(
          "UPDATE users SET currentStreak = ?, bestStreak = ?, completionsCount = ?, lastCheckinDate = ? WHERE id = ?",
          [currentStreak, bestStreak, completionsCount, today, user.id],
          function (err3) {
            if (err3)
              return res.status(500).json({ error: "DB error updating streak" });

            res.json({
              message: "Check-in saved",
              currentStreak,
              bestStreak,
              completionsCount,
            });
          }
        );
      }
    );
  });
});

// ---- Check-in WITH photo evidence ----
app.post(
  "/api/checkin-photo",
  authMiddleware,
  upload.single("photo"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "Photo is required for Fajr check-in" });
    }

    const today = todayISO();

    db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, user) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!user) return res.status(404).json({ error: "User not found" });

      const savePhotoAndRespond = (
        message,
        currentStreak,
        bestStreak,
        completionsCount
      ) => {
        db.run(
          "INSERT INTO checkin_photos (userId, date, photoFilename) VALUES (?, ?, ?)",
          [user.id, today, req.file.filename],
          function (err4) {
            if (err4)
              return res
                .status(500)
                .json({ error: "DB error saving photo evidence" });
            return res.json({
              message,
              currentStreak,
              bestStreak,
              completionsCount,
            });
          }
        );
      };

      if (user.lastCheckinDate === today) {
        return savePhotoAndRespond(
          "Already checked in for today; photo saved as evidence.",
          user.currentStreak || 0,
          user.bestStreak || 0,
          user.completionsCount || 0
        );
      }

      let currentStreak = user.currentStreak || 0;
      let bestStreak = user.bestStreak || 0;
      let completionsCount = user.completionsCount || 0;

      if (!user.lastCheckinDate) {
        currentStreak = 1;
      } else {
        const last = new Date(user.lastCheckinDate);
        const todayDate = new Date(today);
        const diffDays = (todayDate - last) / (1000 * 60 * 60 * 24);

        if (diffDays === 1) {
          currentStreak += 1;
        } else if (diffDays > 1) {
          currentStreak = 1;
        } else if (diffDays < 0) {
          return res
            .status(400)
            .json({ error: "System date issue: check your device clock." });
        }
      }

      if (currentStreak === 40) {
        completionsCount += 1;
      }

      if (currentStreak > bestStreak) bestStreak = currentStreak;

      db.run(
        "INSERT INTO checkins (userId, date) VALUES (?, ?)",
        [user.id, today],
        function (err2) {
          if (err2)
            return res.status(500).json({ error: "DB error inserting checkin" });

          db.run(
            "UPDATE users SET currentStreak = ?, bestStreak = ?, completionsCount = ?, lastCheckinDate = ? WHERE id = ?",
            [currentStreak, bestStreak, completionsCount, today, user.id],
            function (err3) {
              if (err3)
                return res
                  .status(500)
                  .json({ error: "DB error updating streak" });

              savePhotoAndRespond(
                "Check-in and photo saved. JazakAllah khair!",
                currentStreak,
                bestStreak,
                completionsCount
              );
            }
          );
        }
      );
    });
  }
);

// ---- Leaderboard (top 100 global, with city & age) ----
app.get("/api/leaderboard", (req, res) => {
  db.all(
    `
    SELECT id, name, masjid, city, age, photoFilename, currentStreak, bestStreak, completionsCount
    FROM users
    ORDER BY completionsCount DESC, currentStreak DESC, bestStreak DESC, name ASC
    LIMIT 100
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ---- Full leaderboard (no limit) for masjid/age filtering ----
app.get("/api/leaderboard-full", (req, res) => {
  db.all(
    `
    SELECT id, name, masjid, city, age, photoFilename, currentStreak, bestStreak, completionsCount
    FROM users
    ORDER BY completionsCount DESC, currentStreak DESC, bestStreak DESC, name ASC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ---- Hall of Fame ----
app.get("/api/hall-of-fame", (req, res) => {
  db.all(
    `
    SELECT id, name, masjid, city, age, photoFilename, completionsCount, bestStreak
    FROM users
    WHERE completionsCount > 0
    ORDER BY completionsCount DESC, bestStreak DESC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ---- Upload profile photo ----
app.post(
  "/api/upload-photo",
  authMiddleware,
  upload.single("photo"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    const filename = req.file.filename;
    db.run(
      "UPDATE users SET photoFilename = ? WHERE id = ?",
      [filename, req.user.id],
      function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ success: true, filename });
      }
    );
  }
);

// ---- Admin: list all users (with parent & city) ----
app.get("/api/admin/users", authMiddleware, adminMiddleware, (req, res) => {
  db.all(
    `
    SELECT id, name, parentName, email, masjid, city, age, currentStreak, bestStreak, completionsCount, lastCheckinDate, createdAt
    FROM users
    ORDER BY createdAt DESC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ---- Sponsors: public create ----
app.post("/api/sponsors", (req, res) => {
  const { businessName, contactEmail, contactPhone, prizeDescription } = req.body;

  if (!businessName || !prizeDescription) {
    return res
      .status(400)
      .json({ error: "Business name and prize description are required" });
  }

  const stmt = db.prepare(
    "INSERT INTO sponsors (businessName, contactEmail, contactPhone, prizeDescription) VALUES (?, ?, ?, ?)"
  );
  stmt.run(
    businessName.trim(),
    contactEmail ? contactEmail.trim() : null,
    contactPhone ? contactPhone.trim() : null,
    prizeDescription.trim(),
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "DB error saving sponsor" });
      }
      res.json({ success: true });
    }
  );
});

// ---- Sponsors: public list (approved only) ----
app.get("/api/sponsors", (req, res) => {
  db.all(
    `
    SELECT businessName, contactEmail, contactPhone, prizeDescription, createdAt
    FROM sponsors
    WHERE approved = 1
    ORDER BY createdAt DESC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ---- Sponsors: admin list ----
app.get(
  "/api/admin/sponsors",
  authMiddleware,
  adminMiddleware,
  (req, res) => {
    db.all(
      `
      SELECT id, businessName, contactEmail, contactPhone, prizeDescription, createdAt, approved
      FROM sponsors
      ORDER BY createdAt DESC
    `,
      [],
      (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows);
      }
    );
  }
);

// ---- Sponsors: admin approve ----
app.post(
  "/api/admin/sponsors/:id/approve",
  authMiddleware,
  adminMiddleware,
  (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid sponsor id" });
    }

    db.run(
      "UPDATE sponsors SET approved = 1 WHERE id = ?",
      [id],
      function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        if (this.changes === 0) {
          return res.status(404).json({ error: "Sponsor not found" });
        }
        res.json({ success: true });
      }
    );
  }
);

// ---- Admin: check-in photo evidence ----
app.get(
  "/api/admin/checkin-photos",
  authMiddleware,
  adminMiddleware,
  (req, res) => {
    let userId = null;
    if (req.query.userId) {
      const parsed = parseInt(req.query.userId, 10);
      if (!isNaN(parsed)) userId = parsed;
    }

    let sql = `
      SELECT cp.id,
             cp.userId,
             cp.date,
             cp.photoFilename,
             cp.createdAt,
             u.name,
             u.masjid
      FROM checkin_photos cp
      JOIN users u ON u.id = cp.userId
    `;
    const params = [];

    if (userId) {
      sql += " WHERE cp.userId = ?";
      params.push(userId);
    }

    sql += " ORDER BY cp.date DESC, cp.createdAt DESC LIMIT 200";

    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    });
  }
);

// ---- Admin: export 40-day completers as CSV (with city & age) ----
app.get(
  "/api/admin/export-completers",
  authMiddleware,
  adminMiddleware,
  (req, res) => {
    db.all(
      `
      SELECT id, name, parentName, email, masjid, city, age, completionsCount, bestStreak
      FROM users
      WHERE completionsCount > 0
      ORDER BY completionsCount DESC, bestStreak DESC, name ASC
    `,
      [],
      (err, rows) => {
        if (err) return res.status(500).send("DB error");

        const header = "id,childName,parentName,email,masjid,city,age,completionsCount,bestStreak\n";
        const lines = rows.map((u) => {
          const escape = (v) => {
            if (v == null) return "";
            const s = String(v);
            if (s.includes(",") || s.includes('"') || s.includes("\n")) {
              return '"' + s.replace(/"/g, '""') + '"';
            }
            return s;
          };
          return [
            escape(u.id),
            escape(u.name),
            escape(u.parentName),
            escape(u.email),
            escape(u.masjid),
            escape(u.city),
            escape(u.age),
            escape(u.completionsCount),
            escape(u.bestStreak),
          ].join(",");
        });

        const csv = header + lines.join("\n");

        res.setHeader("Content-Type", "text/csv");
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="fajr40-completers.csv"'
        );
        res.send(csv);
      }
    );
  }
);

// ======== START SERVER =========
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

app.listen(PORT, () => {
  console.log(`Fajr40 server running on port ${PORT}`);
});
