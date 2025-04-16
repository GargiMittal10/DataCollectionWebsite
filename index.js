const express = require("express");
const ejsMate = require("ejs-mate");
const path = require("path");
const multer = require("multer");
const xlsx = require("xlsx");
const db = require("./database"); 
const session = require('express-session');
const { sendCredentials, sendCredentialsToAll} = require("./utils/email");
const fs = require("fs");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const app = express();
require("dotenv").config();
const crypto = require("crypto");
const cors = require("cors");
const _ = require("lodash");
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');


const rateLimit = require("express-rate-limit");
const validator = require("validator");
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // Maximum 5 login attempts
  handler: (req, res) => {
      console.warn("❌ Too many failed login attempts:", req.ip);
      res.status(429).json({ error: "❌ Too many failed login attempts. Try again later." });
  }
});
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";

// Multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Save uploaded files to the 'uploads' folder
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); // Keep the original file name
  },
});

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const authenticateToken = (req, res, next) => {
  let token = null;

  // Check if Authorization header contains a Bearer token
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
    console.log("✅ Token extracted from Authorization header:", token);
  } 
  // Fallback: try to get token from cookie
  else if (req.cookies && req.cookies.auth_token) {
    token = req.cookies.auth_token;
    console.log("✅ Token extracted from cookies:", token);
  }

  // If no token found, return a 403 error
  if (!token) {
    console.log("❌ No token provided! Redirecting...");
    return res.redirect("/login");  // ✅ Redirect to login instead of sending JSON error
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // ✅ Attach decoded payload to req.user
    console.log("✅ Token successfully verified! User:", req.user);
    next(); // Proceed to the next middleware/route handler
  } catch (err) {
    console.error("❌ Token verification error:", err);
    return res.redirect("/login");  // ✅ Redirect to login if token is invalid
  }
};

// Initialize multer with the storage configuration
const upload = multer({ storage: storage });
app.use(session({
  secret: "your_secret_key",  // Change this to a secure key
  resave: false,
  saveUninitialized: true,
}));

app.engine("ejs", ejsMate);
app.use(express.static("css"));
app.use(express.static(path.join(__dirname, "hostit-html")));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// Serve the 'uploads' folder as static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static('Faculty-Dashboard_Html'));

// 📌 Routes
app.get('/coordinatordash', authenticateToken, async (req, res) => {
  if (req.user.role !== 'coordinator') {
    return res.redirect('/login');
  }

  try {
    // Fetch student count
    const [studentRows] = await db().execute("SELECT COUNT(*) AS count FROM students");
    const studentCount = studentRows[0].count || 0;

    // Fetch faculty count
    const [facultyRows] = await db().execute("SELECT COUNT(*) AS count FROM faculty");
    const facultyCount = facultyRows[0].count || 0;

    // Fetch mapping count
    const [mappingRows] = await db().execute("SELECT COUNT(*) AS count FROM faculty_student_mapping");
    const mappingCount = mappingRows[0].count || 0;

    res.render('coordinatordash', { 
      user: req.user,
      studentCount,
      facultyCount,
      mappingCount
    });

  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/mapping", (req, res) => res.render("mapping"));
app.get("/download-excel", (req, res) => {
  const filePath = path.join(__dirname, "uploads", "uploadmapping.xlsx");
  res.download(filePath, "uploadmapping.xlsx", (err) => {
      if (err) {
          console.error("Error downloading file:", err);
          res.status(500).send("Error downloading file");
      }
  });
});
app.get("/download-students", (req, res) => {
  const filePath = path.join(__dirname, "uploads", "uploadstudent.xlsx");
  res.download(filePath, "uploadstudent.xlsx", (err) => {
      if (err) {
          console.error("Error downloading file:", err);
          res.status(500).send("Error downloading file");
      }
  });
});
app.get("/download-faculty", (req, res) => {
  const filePath = path.join(__dirname, "uploads", "uploadfaculty.xlsx");
  res.download(filePath, "uploadfaculty.xlsx", (err) => {
      if (err) {
          console.error("Error downloading file:", err);
          res.status(500).send("Error downloading file");
      }
  });
});

app.get("/download-excel-ques", (req, res) => {
  const filePath = path.join(__dirname, "uploads", "questionSample.xlsx");
  res.download(filePath, "Evaluation_Questions_Format.xlsx", (err) => {
      if (err) {
          console.error("Error downloading file:", err);
          res.status(500).send("Error downloading file");
      }
  });
});



app.get("/faculty-dashboard", authenticateToken, (req, res) => {
  if (req.user.role.toLowerCase() !== "faculty") {
      return res.status(403).send("Access denied. Only faculty can view this page.");
  }
  res.render("faculty-dashboard", { user: req.user });
});

app.get("/admindash", authenticateToken, (req, res) => {
  if (req.user.role.toLowerCase() !== "admin") {
      return res.status(403).send("Access denied. Only admins can view this page.");
  }
  res.render("admindash", { user: req.user });
});



// app.get("/admindash", (req, res) => res.render("admindash"));
app.get("/addstudent", (req, res) => res.render("addstudent"));
app.get("/update-questionaire", (req, res) => res.render("update-questionaire"));
app.get("/addfaculty", (req, res) => res.render("addfaculty"));
app.get("/addfacultyview", (req, res) => res.render("addfacultyview"));
app.get("/viewresult", (req, res) => res.render("viewresult"));
app.get("/create-form", (req, res) => res.render("create-form"));
app.get("/update-form", (req, res) => res.render("update-form"));
app.get('/viewmapping', async (req, res) => {
  try {
    const [facultyStudentMapping] = await db().execute(`
      SELECT 
        faculty_student_mapping.id,
        faculty_student_mapping.faculty_id,  
        faculty.faculty_name, 
        students.student_name, 
        skills.skill_name
      FROM faculty_student_mapping
      LEFT JOIN faculty ON faculty_student_mapping.faculty_id = faculty.faculty_id
      LEFT JOIN students ON faculty_student_mapping.student_id = students.student_id
      LEFT JOIN skills ON faculty_student_mapping.skill_id = skills.skill_id;
    `);
    
    const [facultySkillMapping] = await db().execute(`
    SELECT 
    MIN(faculty_skill_mapping.id) AS id,  -- Pick the lowest ID per faculty-skill pair
    faculty_skill_mapping.faculty_id,  
    faculty.faculty_name, 
    skills.skill_name
FROM faculty_skill_mapping
JOIN faculty ON faculty_skill_mapping.faculty_id = faculty.faculty_id
JOIN skills ON faculty_skill_mapping.skill_id = skills.skill_id
GROUP BY 
    faculty_skill_mapping.faculty_id,  
    faculty.faculty_name, 
    skills.skill_name;
    `);

    res.render('viewmapping', { facultyStudentMapping, facultySkillMapping });
  } catch (error) {
    console.error('Error fetching faculty mappings:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get("/login", (req, res) => {
  res.render("login", { 
    forgotPasswordLink: "/forgot-password", 
    signUpLink: "/signup" // Or whatever your sign-up route is
  });
});


function isAuthenticated(req, res, next) {
  if (req.session.user && (req.session.user.role === "coordinator" || req.session.user.role === "faculty"))
{
    return next(); // Allow access
  }
  return res.status(403).send("❌ Access Denied. You are not authorized.");
}


app.get("/viewforms", authenticateToken, (req, res) => {
  if (req.user.role.toLowerCase() !== "faculty") {
      return res.status(403).send("Access denied.");
  }
  res.render("viewforms");
});

app.post("/send-credentials", async (req, res) => {
  console.log(req.body); // Debugging: Check received data
  const { facultyId, email,role } = req.body; 

  if (!facultyId || !email) {
      return res.status(400).send("❌ Missing faculty ID or email.");
  }

  // Generate a random password
  const randomPassword = Math.random().toString(36).slice(-8);
  const saltRounds = 10; // Bcrypt salt rounds

  try {
      // Hash the random password before storing
      const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

      // Store hashed password in the database
      await db().query(
        "INSERT INTO faculty_login ( email, password,role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password = VALUES(password)",
        [email, hashedPassword, role || "faculty"]
    );

      // Send the credentials via email
      await sendCredentials(email, email, randomPassword);

      res.status(200).json({ message: "✅ Credentials sent successfully!" });
  } catch (error) {
      console.error("❌ Error processing request:", error);
      res.status(500).json({ message: "❌ Error sending credentials." });
  }
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password, role } = req.body;
  console.log("🔹 Login attempt:", { email, role });

  if (!email || !password || !role) {
    console.error("❌ Missing credentials:", { email, password, role });
    return res.status(400).json({ error: "Email, password, and role are required." });
  }

  if (!validator.isEmail(email) || !validator.isLength(password, { min: 6 })) {
    return res.status(400).json({ error: "Invalid email or password format." });
  }

  try {
    if (role.toLowerCase() === "admin") {
      if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
        return generateTokenAndRespond(res, email, "admin", "/admindash");
      } else {
        return res.status(401).json({ error: "Invalid admin credentials." });
      }
    }

    if (role.toLowerCase() === "coordinator") {
      if (email === process.env.COORDINATOR_EMAIL && password === process.env.COORDINATOR_PASSWORD) {
        return generateTokenAndRespond(res, email, "coordinator", "/coordinatordash");
      } else {
        return res.status(401).json({ error: "Invalid coordinator credentials." });
      }
    }

    if (role.toLowerCase() === "faculty") {
      let users;
      try {
        [users] = await db().execute("SELECT * FROM faculty_login WHERE email = ?", [email]);
      } catch (dbError) {
        console.error("❌ Database query error:", dbError);
        return res.status(500).json({ error: "Database error. Try again later." });
      }

      if (users.length === 0) {
        console.error("❌ Faculty not found:", email);
        return res.status(404).json({ error: "Invalid email or password." });
      }

      const user = users[0];

      let passwordMatch;
      try {
        passwordMatch = await bcrypt.compare(password, user.password);
      } catch (bcryptError) {
        console.error("❌ Password comparison error:", bcryptError);
        return res.status(500).json({ error: "Password processing error. Try again." });
      }

      if (!passwordMatch) {
        console.error("❌ Incorrect password for:", email);
        return res.status(401).json({ error: "Invalid email or password." });
      }

      return generateTokenAndRespond(res, user.email, user.role, "/faculty-dashboard");
    }

    console.error("❌ Invalid role provided:", role);
    return res.status(400).json({ error: "Invalid role provided." });

  } catch (error) {
    console.error("❌ Login Error:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ✅ Helper function to generate token and send response
function generateTokenAndRespond(res, email, role, redirectUrl) {
  const token = jwt.sign({ email, role }, process.env.SECRET_KEY, { expiresIn: "8h" });

  console.log(`✅ ${role.charAt(0).toUpperCase() + role.slice(1)} login successful. Token generated.`);
  res.clearCookie("auth_token");  
  res.cookie("auth_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    maxAge: 8 * 60 * 60 * 1000
  });

  return res.json({ token, role, redirectUrl });
}



app.get("/studentdata", authenticateToken, async (req, res) => {
  try {
    const username = req.user.email; // Extract faculty username from token

    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }

    const [facultyResult] = await db().query(
      `SELECT faculty_id FROM faculty WHERE email = ?`, 
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id; // Extract faculty_id

    // Check if PRN and skill are provided in the query
    if (req.query.prn && req.query.skill) {
      const prn = req.query.prn;
      const skill = req.query.skill;
      const query = `
          SELECT 
              s.student_name, 
              sk.skill_name, 
              q.Question, 
              r.Result, 
              DATE_FORMAT(r.conducted_date, '%Y-%m-%d') AS conducted_date,
              r.totaltime,
              r.Qno  -- Include Qno in the response
          FROM results r
          JOIN skills sk ON r.skill_id = sk.skill_id
          JOIN students s ON r.student_id = s.student_id
          JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id  
          WHERE r.faculty_id = ? 
          AND s.student_id = ? 
          AND r.skill_id = ?;
      `;
      try {
        const [filteredResults] = await db().query(query, [facultyId, prn, skill]);
        // Calculate total time taken (if any results are returned)
        const totalTimeTaken = filteredResults.length > 0 ? parseFloat(filteredResults[0].totaltime) : 0.0;
        return res.json({ filteredResults, totalTimeTaken });
      } catch (err) {
        console.error("Error fetching student data for PRN and skill:", err);
        return res.status(500).json({ error: "Error fetching data" });
      }
    }

    // If PRN or skill is missing, fetch available PRNs for selection
    const prnQuery = `SELECT DISTINCT student_id FROM results WHERE faculty_id = ?;`;
    try {
      const [prnRows] = await db().query(prnQuery, [facultyId]);
      const availablePRNs = prnRows.map(row => row.student_id);
      res.render("studentdata", { availablePRNs, studentData: [] });
    } catch (error) {
      console.error("Error fetching available PRNs:", error);
      res.status(500).send("Error fetching data");
    }
  } catch (error) {
    console.error("Unexpected error in /studentdata:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});





app.post("/send-credentials-all", async (req, res) => {
  try {
      // Fetch all faculty emails and IDs
      const [facultyList] = await db().query("SELECT email FROM faculty");

      if (facultyList.length === 0) {
          return res.status(404).json({ message: "❌ No faculty members found." });
      }

      let successCount = 0, failureCount = 0;

      // Loop through each faculty member and send credentials
      for (const faculty of facultyList) {
          const randomPassword = Math.random().toString(36).slice(-8);
          const hashedPassword = await bcrypt.hash(randomPassword, 10);

          try {
              // Store the hashed password in the database
              await db().query(
                "INSERT INTO faculty_login (email, password, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password = VALUES(password)",
                [faculty.email, hashedPassword, faculty.role]
              );
              

              // Send email
              await sendCredentials(faculty.email, faculty.role, randomPassword);
              successCount++;
          } catch (error) {
              console.error(`❌ Failed for ${faculty.email}:`, error);
              failureCount++;
          }
      }

      res.json({
          message: `✅ Sent credentials to ${successCount} faculty members. ❌ Failed for ${failureCount}.`
      });
  } catch (error) {
      console.error("❌ Error fetching faculty data:", error);
      res.status(500).json({ message: "❌ Error sending credentials to all." });
  }
});

app.get('/getSkills', async (req, res) => {
  try {
      const [rows] = await db().query('SELECT DISTINCT skill_name FROM skills');

      if (rows.length === 0) {
          console.log("ℹ No skills found in the database.");
      }

      console.log("✅ Skills fetched:", rows); // Debugging log

      const skills = rows.map(row => row.skill_name); // Extract skills
      res.json({ skills });
  } catch (error) {
      console.error('❌ Error fetching skills:', error);
      res.status(500).json({ error: 'Error fetching skills' });
  }
});








app.get("/faculty-dashboard", authenticateToken, (req, res) => {
    
  if (req.user.role.toLowerCase() !== "faculty") {
      return res.status(403).send("Access denied. Only faculty can view this page.");
  }
  res.render("faculty-dashboard", { user: req.user });
});

app.get('/form', (req, res) => {
  try {
      res.render('form'); // Just render the form without any data
  } catch (error) {
      console.error(error);
      res.status(500).send('Error rendering form');
  }
});

app.get("/viewfacultyadmin", authenticateToken, async (req, res) => {
  console.log("✅ Checking access for:", req.user);

  if (!req.user || req.user.role !== "admin") {
      console.log("❌ Unauthorized access attempt by:", req.user);
      return res.redirect("/login");
  }

  try {
      const [facultyList] = await db().query(
          "SELECT faculty_id, faculty_name, email, department FROM faculty ORDER BY CAST(SUBSTRING(faculty_id, 4) AS UNSIGNED) ASC"
      );
      console.log("✅ Faculty list loaded successfully.");
      res.render("viewfacultyadmin", { facultyList, user: req.user }); // ✅ Pass user to EJS
  } catch (error) {
      console.error("❌ Error fetching faculty data:", error);
      res.status(500).send("❌ Error fetching faculty data.");
  }
});

app.get('/getStudentDetails/:student_id', async (req, res) => {
  const student_id = req.params.student_id;

  try {
      const [student] = await db().query("SELECT * FROM students WHERE student_id = ?", [student_id]);

      if (student.length === 0) {
          return res.status(404).json({ error: 'Student not found' });
      }

      res.json(student[0]);
  } catch (error) {
      console.error("❌ Error fetching student details:", error);
      res.status(500).json({ error: 'Error fetching student details' });
  }
});
app.get('/students', (req, res) => {
  const query = 'SELECT student_id, student_name, semester FROM students';

  db.query(query, (err, results) => {
      if (err) {
          console.error('Database query error:', err);
          res.status(500).send('Database error');
      } else {
          console.log('Database Results:', results); // ✅ DEBUG: Print data
          res.render('studentdata', { studentList: results }); // Pass data to EJS
      }
  });
});


app.post("/upload-student", upload.single("studentFile"), async (req, res) => {
  if (!req.file) {
    return res.json({ success: false, message: "❌ Please upload an Excel file." });
  }

  const filePath = path.join(__dirname, "uploads", req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  let studentData = xlsx.utils.sheet_to_json(sheet);

  if (!studentData || studentData.length === 0) {
    return res.json({ success: false, message: "❌ No student data found in the uploaded file." });
  }

  // 🔹 Normalize column names
  studentData = studentData.map(row => {
    return _.mapKeys(row, (value, key) => 
      key.trim().toLowerCase().replace(/\s+/g, "")
    );
  });

  console.log("📊 First row after cleaning:", studentData[0]); // Debugging

  // ✅ Check if required columns are present
  const requiredColumns = ["student_id", "student_name", "email"];
  const fileColumns = Object.keys(studentData[0] || {});

  const hasInvalidColumns = requiredColumns.some(col => !fileColumns.includes(col));
  if (hasInvalidColumns) {
    return res.json({ success: false, message: "❌ Wrong Excel format. Please check your file and try again." });
  }

  try {
    const seenIDs = new Set();
    const duplicateIDs = [];

    const values = studentData
      .map((student) => {
        const studentID = String(student.student_id || "").trim();
        const studentName = String(student.student_name || "").trim();
        const email = String(student.email || "").trim();

        // Check for duplicate student IDs in the same upload
        if (seenIDs.has(studentID)) {
          duplicateIDs.push(studentID);
          return null;
        }
        seenIDs.add(studentID);

        return [studentID, studentName, email, student.year || null, student.institute || null];
      })
      .filter(Boolean); // Remove null entries

    console.log("✅ Extracted Student IDs:", values.map(row => row[0])); // Debugging

    if (duplicateIDs.length > 0) {
      return res.json({ success: false, message: `❌ Duplicate student IDs found in the file: ${[...new Set(duplicateIDs)].join(", ")}` });
    }

    if (values.length > 0) {
      try {
        const [result] = await db().query(
          "INSERT INTO students (student_id, student_name, email, year, institute) VALUES ?",
          [values]
        );

        return res.json({
          success: true,
          message: result.affectedRows > 0 
            ? `✅ Student data uploaded successfully! ${result.affectedRows} rows inserted.` 
            : "❌ No student data was inserted."
        });
      } catch (dbError) {
        if (dbError.code === "ER_DUP_ENTRY") {
          return res.json({ success: false, message: "❌ Duplicate student ID found in the database. Please check your file." });
        }
        throw dbError;
      }
    } else {
      return res.json({ success: false, message: "❌ No valid student data found in the uploaded file." });
    }
  } catch (error) {
    console.error("❌ Error inserting student data:", error);
    res.json({ success: false, message: "❌ Error processing student data. Please try again or check the file format." });
  }
});





// Update viewstudent route
app.get("/viewstudent", authenticateToken, async (req, res) => {
  try {
      const [students] = await db().query(
          "SELECT student_id, student_name, email, year, institute FROM students"
      );
      // Pass req.user into the view as "user"
      res.render("viewstudent", { students, user: req.user });
  } catch (err) {
      console.error("Error fetching student data:", err);
      res.status(500).send("Error fetching student data.");
  }
});

app.get("/viewstudentadmin", authenticateToken, async (req, res) => {
  console.log("✅ Checking access for:", req.user); // Debugging line

  if (!req.user || req.user.role !== "admin") {
    console.log("❌ Unauthorized access attempt by:", req.user);
    return res.redirect("/login");
  }

  try {
      const [students] = await db().query(
          "SELECT student_id, student_name, email, year, institute FROM students"
      );

      console.log("✅ Student list loaded successfully.");
      res.render("viewstudentadmin", { students, user: req.user }); // ✅ Pass user correctly
  } catch (err) {
      console.error("❌ Error fetching student data:", err);
      res.status(500).send("❌ Error fetching student data.");
  }
});


// Update student route
app.post('/update-student', async (req, res) => {
  const { student_id, student_name, email, year, institute } = req.body;
  try {
      await db().query(
          'UPDATE students SET student_name = ?, email = ?, year = ?, institute = ? WHERE student_id = ?',
          [student_name, email, year, institute, student_id]
      );
      res.send('✅ Student updated successfully!');
  } catch (err) {
      console.error(err);
      res.status(500).send('❌ Error updating student.');
  }
});

app.delete('/delete-student/:id', async (req, res) => {
  const studentID = req.params.id;

  try {
    // First, delete the student from the mapping table to prevent foreign key constraint errors
    await db().query('DELETE FROM faculty_student_mapping WHERE student_id = ?', [studentID]);

    // Now delete the student from the students table
    const [result] = await db().query('DELETE FROM students WHERE student_id = ?', [studentID]);

    if (result.affectedRows > 0) {
      res.send("✅ Student deleted successfully!");
    } else {
      res.status(404).send("❌ Student not found.");
    }
  } catch (error) {
    console.error("❌ Error deleting student:", error);
    res.status(500).send("❌ Error deleting student.");
  }
});


// Delete selected students
app.post('/delete-selected', async (req, res) => {
  try {
    const { student_ids } = req.body;
    if (!student_ids || student_ids.length === 0) {
      return res.status(400).send('❌ No students selected.');
    }
    
    const placeholders = student_ids.map(() => '?').join(',');

    // First, delete students from the mapping table to prevent foreign key constraint errors
    await db().query(`DELETE FROM faculty_student_mapping WHERE student_id IN (${placeholders})`, student_ids);
    
    // Now, delete students from the students table
    await db().query(`DELETE FROM students WHERE student_id IN (${placeholders})`, student_ids);

    res.send('✅ Selected students deleted successfully.');
  } catch (err) {
    console.error("❌ Error deleting students:", err);
    res.status(500).send("❌ Database error.");
  }
});


// Delete all students
app.delete('/delete-all', async (req, res) => {
  try {
    // First, delete all student records from the mapping table to prevent foreign key constraint errors
    await db().query('DELETE FROM faculty_student_mapping');

    // Now, delete all students from the students table
    await db().query('DELETE FROM students');

    res.send('✅ All students deleted successfully.');
  } catch (err) {
    console.error("❌ Error deleting all students:", err);
    res.status(500).send("❌ Failed to delete all students.");
  }
});


app.post("/upload-faculty", upload.single("facultyFile"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "❌ Please upload an Excel file." });
  }

  const filePath = path.join(__dirname, "uploads", req.file.filename);
  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    let facultyData = xlsx.utils.sheet_to_json(sheet);

    if (!facultyData || facultyData.length === 0) {
      return res.status(400).json({ error: "❌ No faculty data found in the uploaded file." });
    }

    // **Normalize Column Names**
    const columnMap = {
      "faculty id": "faculty_id",
      "faculty name": "faculty_name",
      "department": "department",
      "email": "email"
    };

    facultyData = facultyData.map(row =>
      _.mapKeys(row, (value, key) => columnMap[key.trim().toLowerCase().replace(/\s+/g, "")] || key)
    );

    console.log("✅ Normalized Data:", facultyData.slice(0, 5));

    // **Required Columns Check**
    const requiredColumns = ["faculty_id", "faculty_name", "department", "email"];
    const sheetColumns = Object.keys(facultyData[0]);
    const missingColumns = requiredColumns.filter(col => !sheetColumns.includes(col));

    if (missingColumns.length > 0) {
      return res.status(400).json({ error: `❌ Incorrect file format. Missing columns: ${missingColumns.join(", ")}` });
    }

    // **Validation Rules**
    const facultyIdRegex = /^FAC\d{3}$/;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    let invalidRows = [];

    const validatedFacultyData = facultyData.filter((faculty, index) => {
      let errors = [];

      if (!faculty.faculty_id || !facultyIdRegex.test(faculty.faculty_id)) {
        errors.push(`Invalid Faculty ID format: ${faculty.faculty_id || "Missing"}`);
      }

      if (!faculty.email || !emailRegex.test(faculty.email)) {
        errors.push(`Invalid Email format: ${faculty.email || "Missing"}`);
      }

      if (errors.length > 0) {
        invalidRows.push({ row: index + 2, errors });
        return false;
      }

      return true;
    });

    if (invalidRows.length > 0) {
      return res.status(400).json({ message: "❌ Errors found in faculty data.", errors: invalidRows });
    }

    // **Sort faculty data numerically by faculty_id**
validatedFacultyData.sort((a, b) => {
  const numA = parseInt(a.faculty_id.replace(/\D/g, ""), 10); // Extracts 101 from "FAC101"
  const numB = parseInt(b.faculty_id.replace(/\D/g, ""), 10);
  return numA - numB; // Sort numerically
});

// **Prepare Data for Insertion**
const values = validatedFacultyData.map((faculty) => [
  faculty.faculty_id.trim(),
  faculty.faculty_name?.trim() || null,
  faculty.department?.trim() || null,
  faculty.email.trim()
]);

    // **Insert Data with Duplicate Key Update**
    const query = `
      INSERT INTO faculty (faculty_id, faculty_name, department, email) VALUES ?
      ON DUPLICATE KEY UPDATE 
      faculty_name = VALUES(faculty_name), 
      department = VALUES(department), 
      email = VALUES(email)
    `;

    const [result] = await db().query(query, [values]);

    if (result.affectedRows > 0) {
      return res.json({ success: "✅ Faculty data uploaded successfully!" });
    } else {
      return res.status(400).json({ error: "❌ No faculty data was inserted. Check your file content." });
    }
  } catch (error) {
    console.error("❌ Error inserting faculty data:", error);
    res.status(500).json({ error: "❌ Error processing faculty data.", details: error.message });
  } finally {
    // **Delete the temporary file**
    fs.unlink(filePath, (err) => {
      if (err) console.error("❌ Error deleting file:", err);
      else console.log(" Temporary file deleted:", filePath);
    });
  }
});

app.get("/viewfaculty", async (req, res) => {
  try {
      const [facultyList] = await db().query("SELECT faculty_id, email FROM faculty");

      console.log("Retrieved Faculty List:", facultyList);
console.log("Type of facultyList:", typeof facultyList, Array.isArray(facultyList));


      res.render("viewfaculty", { facultyList });
  } catch (error) {
      console.error("❌ Error fetching faculty data:", error);
      res.status(500).send("❌ Error fetching faculty data.");
  }
});

// View faculty route
app.get("/viewfacultycoord", authenticateToken, async (req, res) => {
  const user = req.user;
  if (!user || user.role.toLowerCase() !== "coordinator") {
    return res.redirect("/login");
  }
  try {
    const [facultyList] = await db().query(`
      SELECT f.faculty_id, f.faculty_name, f.department, f.email, 
        CASE 
          WHEN fl.password IS NOT NULL THEN '✅ Credentials Sent'
          ELSE '❌ No Credentials Sent'
        END AS credentials_status
      FROM faculty f
      LEFT JOIN faculty_login fl ON f.email = fl.email
      ORDER BY CAST(SUBSTRING(f.faculty_id, 4) AS UNSIGNED) ASC
    `);
    res.render("viewfacultycoord", { user, facultyList });
  } catch (error) {
    console.error("❌ Error fetching faculty data:", error);
    res.status(500).send("❌ Error fetching faculty data.");
  }
});

// Update faculty route
app.put("/update-faculty", async (req, res) => {
  try {
      let { faculty_id, faculty_name, department, email } = req.body;

      if (!faculty_id || !faculty_name || !email) {
          return res.status(400).json({ success: false, message: "❌ Faculty ID, Name, and Email are required." });
      }

      department = department || "N/A";

      // 🔹 Find the old email before updating
      const [faculty] = await db().query(
          "SELECT email FROM faculty WHERE faculty_id = ?", [faculty_id]
      );

      if (faculty.length === 0) {
          return res.status(404).json({ success: false, message: "❌ Faculty not found." });
      }

      const oldEmail = faculty[0].email;

      // 🔹 First update the faculty table
      const [result] = await db().query(
          "UPDATE faculty SET faculty_name = ?, department = ?, email = ? WHERE faculty_id = ?",
          [faculty_name, department, email, faculty_id]
      );

      // 🔹 Then update the faculty_login table
      await db().query(
          "UPDATE faculty_login SET email = ? WHERE email = ?",
          [email, oldEmail]
      );

      if (result.affectedRows > 0) {
          console.log(`✅ Faculty ID ${faculty_id} updated successfully.`);
          res.json({ success: true, message: "✅ Faculty record updated successfully!" });
      } else {
          console.warn(`❌ No updates for Faculty ID ${faculty_id}.`);
          res.status(404).json({ success: false, message: "❌ Faculty not found or no changes made." });
      }
  } catch (error) {
      console.error("❌ Error updating faculty record:", error);
      res.status(500).json({ success: false, message: "❌ Error updating faculty record." });
  }
});





// Delete faculty route
app.delete("/delete-faculty/:faculty_id/:email", async (req, res) => {
  const { faculty_id, email } = req.params;

  try {
      // Delete from faculty_login first to prevent foreign key constraint error
      await db().query("DELETE FROM faculty_login WHERE email = ?", [email]);

      // Now delete from faculty
      const [result] = await db().query(
          "DELETE FROM faculty WHERE faculty_id = ? AND email = ?",
          [faculty_id, email]
      );

      if (result.affectedRows > 0) {
          res.send("✅ Faculty deleted successfully!");
      } else {
          res.status(404).send("❌ Faculty not found.");
      }
  } catch (error) {
      console.error("❌ Error deleting faculty:", error);
      res.status(500).send("❌ Error deleting faculty.");
  }
});


// Delete all faculty
app.delete("/delete-all-faculty", async (req, res) => {
  try {
      // Delete mappings first to prevent foreign key constraint errors
      await db().query("DELETE FROM faculty_student_mapping");
      await db().query("DELETE FROM faculty_skill_mapping");

      // Delete faculty login records (optional: if login records exist)
      await db().query("DELETE FROM faculty_login");

      // Now delete all faculty records
      const [result] = await db().query("DELETE FROM faculty");

      if (result.affectedRows > 0) {
          res.json({ message: "✅ All faculty records deleted successfully!" });
      } else {
          res.status(404).json({ message: "❌ No faculty records found to delete." });
      }
  } catch (error) {
      console.error("❌ Error deleting all faculty records:", error);
      res.status(500).json({ message: "❌ Error deleting all faculty records." });
  }
});



app.delete("/delete-selected-faculty", async (req, res) => {
  const { selectedFaculty } = req.body;

  if (!selectedFaculty || selectedFaculty.length === 0) {
    return res.status(400).json({ message: "❌ No faculty selected for deletion." });
  }

  try {
    // Delete from faculty_login first
    const emailList = selectedFaculty.map(faculty => faculty.email);
    await db().query("DELETE FROM faculty_login WHERE email IN (?)", [emailList]);

    // Now delete from faculty
    const whereClause = selectedFaculty.map(() => "(email = ?)").join(" OR ");
    const values = selectedFaculty.flatMap(faculty => [faculty.email]);

    const [result] = await db().query(
      `DELETE FROM faculty WHERE ${whereClause}`,
      values
    );

    if (result.affectedRows > 0) {
      return res.json({ message: "✅ Selected faculty records deleted successfully!" });
    } else {
      return res.status(404).json({ message: "❌ No matching faculty records found." });
    }
  } catch (error) {
    console.error("❌ Error deleting selected faculty records:", error);
    return res.status(500).json({ message: "❌ Error deleting selected faculty records." });
  }
});

app.get("/result", async (req, res) => {
  try {
      // Fetch all student IDs
      const [students] = await db().query("SELECT student_id FROM students");
      const studentIdList = students.map(student => student.student_id);

      // Get student_id from query parameters
      const studentId = req.query.student_id || null;
      let results = [];

      // Fetch results only if studentId is provided
      if (studentId) {
          [results] = await db().query(`
              SELECT 
                  s.student_name, 
                  sk.skill_name, 
                  q.Question, 
                  r.Result 
              FROM results r
              JOIN skills sk ON r.skill_id = sk.skill_id
              JOIN students s ON r.student_id = s.student_id
              JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id  
              WHERE s.student_id = ?;
          `, [studentId]);
      }

      res.render('viewresult', { studentIdList, studentId, results });
  } catch (error) {
      console.error("❌ Error fetching results:", error);
      res.status(500).send("❌ Error fetching results.");
  }
}); 

// Delete a single student mapping
app.post('/delete-student-viewmapping/:id', (req, res) => {
  const id = req.params.id;
  const query = 'DELETE FROM faculty_student_mapping WHERE id = ?';

  db.query(query, [id], (err, result) => {
      if (err) {
          console.error("Error deleting student mapping:", err);
          return res.status(500).json({ message: "Failed to delete student mapping" });
      }
      res.json({ message: "Student mapping deleted successfully", affectedRows: result.affectedRows });
  });
});

// Delete a single skill mapping
app.post('/delete-skill-viewmapping/:id', (req, res) => {
  const id = req.params.id;
  const query = 'DELETE FROM faculty_skill_mapping WHERE id = ?';

  db.query(query, [id], (err, result) => {
      if (err) {
          console.error("Error deleting skill mapping:", err);
          return res.status(500).json({ message: "Failed to delete skill mapping" });
      }
      res.json({ message: "Skill mapping deleted successfully", affectedRows: result.affectedRows });
  });
});

// Delete selected student mappings
app.post('/delete-selected', async (req, res) => {
  try {
    const { student_ids } = req.body;
    if (!student_ids || student_ids.length === 0) {
      return res.status(400).send('❌ No students selected.');
    }
    const placeholders = student_ids.map(() => '?').join(',');
    await db().query(`DELETE FROM students WHERE student_id IN (${placeholders})`, student_ids);
    res.send('✅ Selected students deleted successfully.');
  } catch (err) {
    console.error("❌ Error deleting students:", err);
    res.status(500).send("❌ Database error.");
  }
});

// Delete selected skill mappings
app.post('/delete-selected-skill-viewmapping', (req, res) => {
  const ids = req.body.ids;
  if (!ids || ids.length === 0) {
      return res.status(400).json({ message: "No records selected" });
  }

  const query = 'DELETE FROM faculty_skill_mapping WHERE id IN (?)';
  db.query(query, [ids], (err, result) => {
      if (err) {
          console.error("Error deleting selected skill mappings:", err);
          return res.status(500).json({ message: "Failed to delete selected skill mappings" });
      }
      res.json({ message: "Selected skill mappings deleted successfully", affectedRows: result.affectedRows });
  });
});

// Delete all student mappings
app.delete('/delete-all', async (req, res) => {
  try {
    // First, delete all mappings to avoid foreign key constraint issues
    await db().query('DELETE FROM faculty_student_mapping');

    // Then, delete all student records
    await db().query('DELETE FROM students');

    res.send('✅ All students and their mappings deleted successfully.');
  } catch (err) {
    console.error("❌ Error deleting all students:", err);
    res.status(500).send('❌ Failed to delete all students.');
  }
});

// Delete all skill mappings
app.post('/delete-all-skill-viewmapping', (req, res) => {
  const query = 'DELETE FROM faculty_skill_mapping';
  db.query(query, (err, result) => {
      if (err) {
          console.error("Error deleting all skill mappings:", err);
          return res.status(500).json({ message: "Failed to delete all skill mappings" });
      }
      res.json({ message: "All skill mappings deleted successfully", affectedRows: result.affectedRows });
  });
});




app.get("/forgot-password", (req,res) => res.render("forgot-password"));

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).send("❌ Please provide an email.");
  }

  try {
    // Check if the email exists in faculty_login table
    const [user] = await db().execute(
      "SELECT * FROM faculty_login WHERE email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(404).send("❌ Email not found in records.");
    }

    // Generate a new random password
    const randomPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(randomPassword, 10);

    // Update the new password in the database
    await db().execute(
      "UPDATE faculty_login SET password = ? WHERE email = ?",
      [hashedPassword, email]
    );

    // Send new credentials via email
    await sendCredentials(email, email, randomPassword);

    res.status(200).send("✅ New credentials sent to your email.");
  } catch (error) {
    console.error("❌ Error in forgot-password route:", error);
    res.status(500).send("❌ Internal server error.");
  }
});


app.post("/submit-mapping", upload.single("studentFile"), async (req, res) => {
  if (!req.file) return res.status(400).send("❌ No file uploaded.");

  const filePath = path.join(__dirname, "uploads", req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  const rows = xlsx.utils.sheet_to_json(sheet);

  if (!rows.length) return res.status(400).send("❌ Empty file uploaded.");

  try {
    const facultyIds = new Set();
    const studentIds = new Set();
    const skillIds = new Set();
    const facultyStudentInsertQueries = [];
    const facultySkillInsertQueries = [];

    let lastFacultyId = null;
    let lastSkillId = null; // Store last valid Skill ID

for (const row of rows) {
    const faculty_id = row["faculty_id"] ? String(row["faculty_id"]).trim() : null;
    const skill_id = row["skill_id"] ? String(row["skill_id"]).trim() : lastSkillId;
    const student_id = row["student_id"] ? String(row["student_id"]).trim() : null;

    // ✅ Update lastSkillId only if the current row has a valid skill_id
    if (row["skill_id"]) {
        lastSkillId = skill_id;
    }

    if (faculty_id) facultyIds.add(faculty_id);
    if (student_id) studentIds.add(student_id);
    if (skill_id) skillIds.add(skill_id); // Ensure we track all unique skills

    if (faculty_id && skill_id) {
        facultySkillInsertQueries.push([faculty_id, skill_id]);
    }

    if (faculty_id && student_id && skill_id) {
        facultyStudentInsertQueries.push([faculty_id, student_id, skill_id]);
    }
}

    console.log("✅ Extracted Faculty IDs:", Array.from(facultyIds));
    console.log("✅ Extracted Student IDs:", Array.from(studentIds));
    console.log("✅ Extracted Skill IDs:", Array.from(skillIds));

    // 🔹 Fetch faculty names
    const [facultyData] = await db().query(
      "SELECT faculty_id, faculty_name FROM faculty WHERE faculty_id IN (?)",
      [Array.from(facultyIds)]
    );
    const facultyMap = Object.fromEntries(facultyData.map(row => [row.faculty_id, row.faculty_name]));

    // 🔹 Fetch student names
    const [studentData] = await db().query(
      "SELECT student_id, student_name FROM students WHERE student_id IN (?)",
      [Array.from(studentIds)]
    );
    const studentMap = Object.fromEntries(studentData.map(row => [row.student_id, row.student_name]));

    
    let skillMap = {}; // Default empty object

    if (skillIds.size > 0) {  // Run query only if skillIds is not empty
        const [skillData] = await db().query(
            "SELECT skill_id, skill_name FROM skills WHERE skill_id IN (?)",
            [Array.from(skillIds)]
        );
        skillMap = Object.fromEntries(skillData.map(row => [row.skill_id, row.skill_name]));
    } else {
        console.log("⚠ No skills found, skipping SQL query.");
    }
    

    console.log("✅ Faculty Names:", facultyMap);
    console.log("✅ Student Names:", studentMap);
    console.log("✅ Skill Names:", skillMap);

    // 🔹 Identify missing Faculty, Students, and Skills
    const missingFaculty = [...facultyIds].filter(id => !facultyMap[id]);
    const missingStudents = [...studentIds].filter(id => !studentMap[id]);
    const missingSkills = [...skillIds].filter(id => !skillMap[id]);

    if (missingFaculty.length || missingStudents.length || missingSkills.length) {
      console.log("❌ Missing Faculty:", missingFaculty);
      console.log("❌ Missing Students:", missingStudents);
      console.log("❌ Missing Skills:", missingSkills);

      return res.status(400).json({
        message: "❌ Some faculty, students, or skills do not exist in the database.",
        missingFaculty,
        missingStudents,
        missingSkills
      });
    }

    // 🔹 Insert Data if Validation Passed
    if (facultySkillInsertQueries.length > 0) {
      await db().query(
        "INSERT IGNORE INTO faculty_skill_mapping (faculty_id, skill_id) VALUES ?",
        [facultySkillInsertQueries]
      );
    }

    if (facultyStudentInsertQueries.length > 0) {
      await db().query(
        "INSERT IGNORE INTO faculty_student_mapping (faculty_id, student_id, skill_id) VALUES ?",
        [facultyStudentInsertQueries]
      );
    }
    console.log("🟢 Faculty-Skill Insert Queries:", facultySkillInsertQueries);
console.log("🟢 Faculty-Student Insert Queries:", facultyStudentInsertQueries);


    res.send("✅ Mapping uploaded successfully!");
  } catch (error) {
    console.error("❌ Error:", error);
    res.status(500).send("❌ Error processing file.");
  }
});


app.get("/logout", (req, res) => {
  res.clearCookie("auth_token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict"
  });

  console.log("✅ User logged out successfully.");
  res.redirect("/login");  // ✅ Redirect user to login page after logout
});
                                                                  
// API: Get Faculty Name based on token (using email from token)
app.get('/getFacultyName', async (req, res) => {
  try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(401).json({ error: "Unauthorized: Token missing or malformed" });
      }
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, SECRET_KEY);
      if (!decoded.email) {
          return res.status(400).json({ error: "Invalid token: Email not found" });
      }
      const email = decoded.email;
      const [rows] = await db().execute(`
        SELECT faculty_name 
        FROM faculty 
        WHERE email = ?
    `, [email]);
    


      if (rows.length === 0) {
          return res.status(404).json({ error: "Faculty not found" });
      }
      res.json({ facultyName: rows[0].faculty_name });
  } catch (error) {
      console.error("Error fetching faculty name:", error);
      if (error.name === "JsonWebTokenError") {
          return res.status(401).json({ error: "Invalid token" });
      } else if (error.name === "TokenExpiredError") {

          return res.status(401).json({ error: "Token expired" });
      }
      res.status(500).json({ error: "Internal server error" });
  }
});


app.get('/getFacultySkills', authenticateToken, async (req, res) => {
  try {
    const username = req.user.email; // Extract username from the token

    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }

    const [facultyResult] = await db().query(
      `SELECT faculty_id FROM faculty WHERE email = ?`,
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id; // Extract faculty_id

    
    const [skills] = await db().query(
      `SELECT distinct s.skill_id, s.skill_name 
       FROM faculty_skill_mapping fsm
       JOIN skills s ON fsm.skill_id = s.skill_id
       WHERE fsm.faculty_id = ?`, 
      [facultyId]
    );

    res.json(skills);
  } catch (error) {
    console.error("❌ Error fetching faculty skills:", error);
    res.status(500).json({ error: "Failed to fetch skills" });
  }
});



app.get('/getStudentsBySkill/:skill_id', authenticateToken, async (req, res) => {
  try {
    const skillId = req.params.skill_id;
    const username = req.user.email; // Extract faculty username from token

    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }

    // Query faculty table for the faculty_id
    const [facultyResult] = await db().query(
      `SELECT faculty_id FROM faculty WHERE email = ?`,
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id; // Extract faculty_id

    // Fetch students mapped to this faculty for the selected skill
    const [students] = await db().query(
      `SELECT s.student_id, s.student_name
       FROM faculty_student_mapping fsm
       JOIN students s ON fsm.student_id = s.student_id
       WHERE fsm.faculty_id = ? AND fsm.skill_id = ?`,
      [facultyId, skillId]
    );

    res.json(students);
  } catch (error) {
    console.error("❌ Error fetching students for selected skill:", error);
    res.status(500).json({ error: "Failed to fetch students" });
  }
});

app.get('/fetch-questions/:skillId', async (req, res) => {
  try {
    const [rows] = await db().execute(
      'SELECT * FROM evaluation_questions WHERE skill_id = ?', 
      [req.params.skillId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Error fetching questions' });
  }
});


app.post('/submit-results', authenticateToken, async (req, res) => {
  const results = req.body.results;
  try {
    const username = req.user.email; // Extract username from the token

    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }


    const [facultyResult] = await db().query(
      `SELECT faculty_id FROM faculty WHERE email = ?`, 
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const faculty_id = facultyResult[0].faculty_id; // Extract faculty_id

    for (const result of results) {
      const { student_id, skill_id, Qno, Result, totaltime, conducted_time, conducted_date } = result;

      const query = `
        INSERT INTO Results (student_id, faculty_id, skill_id, Qno, totaltime, conducted_time, Result, conducted_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      await db().query(query, [student_id, faculty_id, skill_id, Qno, totaltime, conducted_time, Result, conducted_date]);
    }

    res.status(200).json({ message: "Results successfully saved!" });
  } catch (error) {
    console.error("Error inserting results:", error);
    res.status(500).json({ error: "Failed to save results" });
  }
});

app.put("/updateStudentData", async (req, res) => {
  const { prn, updatedAnswers, totaltime } = req.body;

  try {
      if (!Array.isArray(updatedAnswers) || updatedAnswers.length === 0) {
          return res.status(400).json({ message: "No answers provided" });
      }

      const conductedDate = updatedAnswers.length > 0 ? updatedAnswers[0].conducted_date : null;
      if (!conductedDate) {
          return res.status(400).json({ message: "Conducted date is missing" });
      }

      // Ensure student exists before updating
      const [existingStudent] = await db().query(
          "SELECT * FROM results WHERE student_id = ? AND conducted_date = ?;",
          [prn, conductedDate]
      );

      if (existingStudent.length === 0) {
          return res.status(404).json({ message: "Student data not found" });
      }

      for (const answer of updatedAnswers) {
          await db().query(
              "UPDATE results SET Result = ? WHERE student_id = ? AND qno = ? AND conducted_date = ?;",
              [answer.result, prn, answer.qno, conductedDate]
          );
      }

      if (totaltime && typeof totaltime[conductedDate] !== "undefined") {
          const totalTimeValue = totaltime[conductedDate];

          await db().query(
              "UPDATE results SET totaltime = ? WHERE student_id = ? AND conducted_date = ?;",
              [totalTimeValue, prn, conductedDate]
          );
      }

      res.status(200).json({ message: "Student data updated successfully" });
  } catch (error) {
      console.error("Error updating student data:", error);
      res.status(500).json({ message: "Internal Server Error" });
  }
});


app.get('/student-details/:prn', async (req, res) => {
  try {
      const prn = req.params.prn;
      const [result] = await db.execute(`
          SELECT student_name, semester
          FROM students
          WHERE student_id = ?;
      `, [prn]);
      if (result.length > 0) {
          const student = result[0];
          res.json(student);
      } else {
          res.status(404).json({ message: 'Student not found' });
      }
  } catch (error) {
      console.error(error);
      res.status(500).send('Error fetching student details');
  }
});

async function getNextSkillId() {
    try {
        const [rows] = await db().query('SELECT MAX(skill_id) AS max_id FROM skills');
        return (rows[0].max_id || 0) + 1;
    } catch (error) {
        console.error("Error getting next skill ID:", error);
        throw error;
    }
}

app.post('/add-skill', upload.single('questionFile'), async (req, res) => {
    const { skillName } = req.body;
    const filePath = req.file?.path;

    if (!skillName || !filePath) {
        return res.status(400).send('Skill name and Excel file are required.');
    }

    try {
        const skillId = await getNextSkillId();

        await db().query('INSERT INTO skills (skill_id, skill_name) VALUES (?, ?)', [skillId, skillName]);

        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheetData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        for (let row of sheetData) {
            if (row.Qno && row.Question) {
                await db().query(
                    'INSERT INTO evaluation_questions (Qno, Question, skill_id) VALUES (?, ?, ?)',
                    [row.Qno, row.Question, skillId]
                );
            }
        }

        fs.unlinkSync(filePath);
        res.send('Skill and questions added successfully.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.get("/api/skills", async (req, res) => {
  try {
    const [rows] = await db().query("SELECT * FROM skills");
    res.json(rows); // e.g. [{skill_id:1, skill_name:'Skill One'}, ...]
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error fetching skills" });
  }
});

app.get("/api/evaluation-questions", async (req, res) => {
  const skillId = req.query.skill_id;
  if (!skillId) {
    return res.status(400).json({ message: "skill_id is required" });
  }

  try {
    const [rows] = await db().query(
      "SELECT Qno, Question, skill_id FROM evaluation_questions WHERE skill_id = ?",
      [skillId]
    );
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error fetching questions" });
  }
});

app.post("/api/evaluation-questions", async (req, res) => {
  const { qno, question, skill_id } = req.body;

  // Validate input
  if (!qno || !question || !skill_id) {
    return res
      .status(400)
      .json({ message: "qno, question, and skill_id are required" });
  }

  try {
    // Insert question with user-supplied Qno
    const [result] = await db().query(
      "INSERT INTO evaluation_questions (Qno, Question, skill_id) VALUES (?, ?, ?)",
      [qno, question, skill_id]
    );

    res.json({ message: "Question added successfully" });
  } catch (error) {
    console.error("Error adding question:", error);
    res.status(500).json({ message: "Failed to add question" });
  }
});

app.put("/api/evaluation-questions/:oldQno", async (req, res) => {
  const { oldQno } = req.params;
  const { newQno, question } = req.body;

  if (!newQno || !question) {
    return res
      .status(400)
      .json({ message: "newQno and question are required" });
  }

  try {
    // Update Qno and Question
    const [result] = await db().query(
      "UPDATE evaluation_questions SET Qno = ?, Question = ? WHERE Qno = ?",
      [newQno, question, oldQno]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Question not found" });
    }

    res.json({ message: "Question updated successfully" });
  } catch (error) {
    console.error("Error editing question:", error);
    res.status(500).json({ message: "Failed to edit question" });
  }
});

// 5️⃣ DELETE A QUESTION
//    DELETE /api/evaluation-questions/:qno
app.delete("/api/evaluation-questions/:qno", async (req, res) => {
  const { qno } = req.params;

  try {
    const [result] = await db().query(
      "DELETE FROM evaluation_questions WHERE Qno = ?",
      [qno]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Question not found" });
    }

    res.json({ message: "Question deleted successfully" });
  } catch (error) {
    console.error("Error deleting question:", error);
    res.status(500).json({ message: "Failed to delete question" });
  }
});

// 📌 Start Server
app.listen(3000, () => console.log("🚀 Server running on port 3000"));
