require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Database connection pool configured for TiDB Cloud SSL
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "test",
  port: Number(process.env.DB_PORT) || 4000,
  ssl:
    process.env.DB_HOST && process.env.DB_HOST !== "localhost"
      ? { rejectUnauthorized: true }
      : undefined,
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_key";

// 1. Health Check
app.get("/", (req, res) => {
  res.json({ message: "Auth API is running live!" });
});

// 2. Sign Up (Updated with Email, Mobile, Gender, and Terms)
app.post("/signup", async (req, res) => {
  const { username, password, email, mobile, gender, acceptedTerms } = req.body;

  // Basic presence validation
  if (!username || !password || !email || !mobile || !gender) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Checkbox: Terms and conditions validation
  if (acceptedTerms !== true) {
    return res.status(400).json({ error: "You must accept the terms and conditions" });
  }

  // Radio button: Gender validation
  const genderLower = gender.toLowerCase();
  if (!['male', 'female'].includes(genderLower)) {
    return res.status(400).json({ error: "Gender must be 'male' or 'female'" });
  }

  // Regex: 10-digit mobile number validation
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: "Mobile number must be exactly 10 digits" });
  }

  // Regex: Basic email validation
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {
    // Check if Username, Email, or Mobile already exists
    const [existing] = await pool.query(
      "SELECT USERNAME, EMAIL, MOBILE FROM USERS WHERE USERNAME = ? OR EMAIL = ? OR MOBILE = ?",
      [username, email, mobile]
    );

    if (existing.length > 0) {
      const duplicate = existing[0];
      if (duplicate.USERNAME === username) return res.status(409).json({ error: "Username already taken" });
      if (duplicate.EMAIL === email) return res.status(409).json({ error: "Email already registered" });
      if (duplicate.MOBILE === mobile) return res.status(409).json({ error: "Mobile number already registered" });
    }

    // Hash password and insert all data
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO USERS (USERNAME, EMAIL, MOBILE, GENDER, ACCEPTED_TERMS, PASSWORD) VALUES (?, ?, ?, ?, ?, ?)",
      [username, email, mobile, genderLower, acceptedTerms, hashedPassword]
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
      createdData: {
        username: username,
        email: email,
        mobile: mobile,
        gender: genderLower,
        password_used: password // Included for your local testing purposes
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const [rows] = await pool.query(
      "SELECT * FROM USERS WHERE USERNAME = ?",
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.PASSWORD);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user.ID, username: user.USERNAME },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Get Single User by ID (Updated to return new fields)
app.get("/users/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      "SELECT ID, USERNAME, EMAIL, MOBILE, GENDER FROM USERS WHERE ID = ?",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Change Password by ID
app.put("/users/:id/password", async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      error: "currentPassword and newPassword are required"
    });
  }

  try {
    const [rows] = await pool.query("SELECT * FROM USERS WHERE ID = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(currentPassword, user.PASSWORD);
    if (!match) {
      return res.status(401).json({ error: "Current password does not match" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE USERS SET PASSWORD = ? WHERE ID = ?", [
      hashedNewPassword,
      id
    ]);

    res.json({
      message: "Password updated successfully",
      userId: id
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Change Username by ID
app.put("/users/:id/username", async (req, res) => {
  const { id } = req.params;
  const { newUsername, password } = req.body;

  if (!newUsername || !password) {
    return res.status(400).json({
      error: "newUsername and password are required"
    });
  }

  try {
    const [rows] = await pool.query("SELECT * FROM USERS WHERE ID = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.PASSWORD);
    if (!match) {
      return res.status(401).json({ error: "Invalid password" });
    }

    // Check if requested username is taken by someone else
    const [existing] = await pool.query(
      "SELECT ID FROM USERS WHERE USERNAME = ? AND ID != ?",
      [newUsername, id]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: "Username already taken" });
    }

    await pool.query("UPDATE USERS SET USERNAME = ? WHERE ID = ?", [
      newUsername,
      id
    ]);

    res.json({
      message: "Username updated successfully",
      userId: id,
      newUsername
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Delete User by ID
app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM USERS WHERE ID = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      message: "User deleted successfully",
      deletedUserId: id
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 8. PATCH: Update specific fields (Partial Update)
app.patch("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { email, mobile, gender } = req.body;

  if (!email && !mobile && !gender) {
    return res.status(400).json({ error: "Please provide email, mobile, or gender to update" });
  }

  const updates = [];
  const values = [];

  if (email) {
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Invalid email" });
    updates.push("EMAIL = ?");
    values.push(email);
  }

  if (mobile) {
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: "Mobile must be 10 digits" });
    updates.push("MOBILE = ?");
    values.push(mobile);
  }

  if (gender) {
    const genderLower = gender.toLowerCase();
    if (!['male', 'female'].includes(genderLower)) return res.status(400).json({ error: "Gender must be male or female" });
    updates.push("GENDER = ?");
    values.push(genderLower);
  }

  try {
    if (email || mobile) {
      const [existing] = await pool.query(
        "SELECT EMAIL, MOBILE FROM USERS WHERE (EMAIL = ? OR MOBILE = ?) AND ID != ?",
        [email || null, mobile || null, id]
      );
      if (existing.length > 0) {
        return res.status(409).json({ error: "Email or Mobile already in use by another user" });
      }
    }

    values.push(id);
    const query = `UPDATE USERS SET ${updates.join(", ")} WHERE ID = ?`;
    
    const [result] = await pool.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User updated successfully via PATCH", updatedFields: Object.keys(req.body) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 9. PUT: Replace entire user profile (Full Update)
app.put("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { username, email, mobile, gender, acceptedTerms } = req.body;

  if (!username || !email || !mobile || !gender || acceptedTerms === undefined) {
    return res.status(400).json({ error: "PUT requires all fields: username, email, mobile, gender, acceptedTerms" });
  }

  const genderLower = gender.toLowerCase();
  if (!['male', 'female'].includes(genderLower)) return res.status(400).json({ error: "Invalid gender" });
  if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: "Mobile must be 10 digits" });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Invalid email" });

  try {
    const [existing] = await pool.query(
      "SELECT USERNAME, EMAIL, MOBILE FROM USERS WHERE (USERNAME = ? OR EMAIL = ? OR MOBILE = ?) AND ID != ?",
      [username, email, mobile, id]
    );

    if (existing.length > 0) {
       return res.status(409).json({ error: "Username, Email, or Mobile already taken by another user" });
    }

    const [result] = await pool.query(
      "UPDATE USERS SET USERNAME = ?, EMAIL = ?, MOBILE = ?, GENDER = ?, ACCEPTED_TERMS = ? WHERE ID = ?",
      [username, email, mobile, genderLower, acceptedTerms, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User completely replaced successfully via PUT" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 10. Logout (New Endpoint)
app.post("/logout", (req, res) => {
  // Optional: Extract token from header if you want to verify it before logging out
  const authHeader = req.headers["authorization"];
  
  // Since JWT is stateless, logout is handled client-side by deleting the token.
  // This endpoint serves as a clean confirmation response for API test suites.
  res.json({
    message: "Logged out successfully. Please clear your token on the client side."
  });
});

// Dynamic Port for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth API running on port ${PORT}`);
});