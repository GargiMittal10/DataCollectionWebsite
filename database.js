require('dotenv').config();
const mysql = require("mysql2");

// 📌 MySQL Connection Configuration
const db = mysql.createConnection({
    host: process.env.DB_HOST,        // Use the host from .env
    user: process.env.DB_USER,        // Use the user from .env
    password: process.env.DB_PASSWORD, // Use the password from .env
    database: process.env.DB_DATABASE, 
    waitForConnections: true,
    connectionLimit: 13,  // ✅ Only allow 10 active connections at a time
    queueLimit: 75
});

// 📌 Connect to MySQL
db.query("SELECT 1", (err, results) => {
  if (err) {
      console.error("❌ MySQL Connection Failed:", err);
      return;
  }
  console.log("✅ Connected to MySQL Database");
});

// 📌 Export the Connection
module.exports = db;
