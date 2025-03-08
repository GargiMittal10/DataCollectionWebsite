require('dotenv').config();
const mysql = require("mysql2");

// 📌 MySQL Connection Configuration
const db = mysql.createConnection({
    host: process.env.DB_HOST,        // Use the host from .env
    user: process.env.DB_USER,        // Use the user from .env
    password: process.env.DB_PASSWORD, // Use the password from .env
    database: process.env.DB_DATABASE, 
});

// 📌 Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("❌ MySQL Connection Failed:", err);
    return;
  }
  console.log("✅ Connected to MySQL Database");
   // 📌 Create Database and Tables
   createDatabaseAndTables();
});

const createDatabaseAndTables = () => {
  // Create the database "schs" if it doesn't exist
  const createDatabaseQuery = "CREATE DATABASE IF NOT EXISTS schs";
  
  db.query(createDatabaseQuery, (err) => {
    if (err) {
      console.error("❌ Error creating database:", err);
    } else {
      console.log("✅ Database 'schs' created (or already exists)");

      // Switch to the 'schs' database
      const useDatabaseQuery = "USE schs";
      db.query(useDatabaseQuery, (err) => {
        if (err) {
          console.error("❌ Error selecting database 'schs':", err);
        } else {
          console.log("✅ Using 'schs' database");

          // Create the 'faculty' table if it doesn't exist
          const createFacultyTable = `
            CREATE TABLE IF NOT EXISTS faculty (
              faculty_id VARCHAR(100),
              faculty_name VARCHAR(100),
              department VARCHAR(50),
              email VARCHAR(200),
              PRIMARY KEY(email, faculty_id)
            );
          `;

          db.query(createFacultyTable, (err) => {
            if (err) {
              console.error("❌ Error creating faculty table:", err);
            } else {
              console.log("✅ Faculty table created (or already exists)");

              // Add unique constraints to 'faculty_id' and 'email'
              const alterFacultyTable = `
                ALTER TABLE faculty
                ADD UNIQUE (faculty_id),
                ADD UNIQUE (email);
              `;

              db.query(alterFacultyTable, (err) => {
                if (err) {
                  console.error("❌ Error adding unique constraints to faculty table:", err);
                } else {
                  console.log("✅ Unique constraints added to faculty_id and email");
                }
              });
            }
          });
        }
      });
    }
  });
};


// 📌 Export the Connection
module.exports = db;
