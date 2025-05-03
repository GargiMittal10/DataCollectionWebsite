require("dotenv").config();
const express = require("express");
const ejsMate = require("ejs-mate");
const path = require("path");
const multer = require("multer");
const xlsx = require("xlsx");
const db = require("./database"); 
const session = require('express-session');
const { sendCredentials, sendCredentialsToAll,sendOtpEmail} = require("./utils/email");
const fs = require("fs");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const app = express();
const axios = require("axios");
const crypto = require("crypto");
const cors = require("cors");
const _ = require("lodash");
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const rateLimit = require("express-rate-limit");
const { spawn } = require("child_process");
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
const otpStore = new Map();
const stopword = require("stopword");
const { Writable } = require("stream");
const nlp = require('compromise');
const csv = require("csv-parser");
const cron = require("node-cron");
const csvUrl = "https://docs.google.com/spreadsheets/d/1LN5J-yPzwILeRkCgzKwbzX0QTwA8gvwxzxpqvtJXqTI/export?format=csv";
const facultyCsvUrl = "https://docs.google.com/spreadsheets/d/1HroVSFzELqAPjOEASNM-eQBDdZuAXk_KY8VoFgYQ76I/export?format=csv";
;

const resources = JSON.parse(fs.readFileSync('resources.json', 'utf8'));
const rules = {
  hi: "Hello! How can I assist you today?",
  hello: "Hi there! Need any help?",
  bye: "Goodbye! Have a great day.",
  help: "Sure, I'm here to assist you. Ask me anything!",
  thanks: "You're welcome!",
};
const synonymMap = {
  "resources": ["materials", "content", "training", "learning", "courses", "videos", "books", "guide", "pdf", "slides"]
};
const normalizeMessage = (msg) => {
  const lowerMsg = msg.toLowerCase().trim();

  for (const key in synonymMap) {
    for (const synonym of synonymMap[key]) {
      if (lowerMsg.includes(synonym)) {
        return key; // e.g., 'resources'
      }
    }
  }

  if (lowerMsg.match(/bye{2,}|goodbye/)) return 'bye';
  if (lowerMsg.match(/\b(hi|hello)\b/)) return 'hello';

  return lowerMsg;
};


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
  saveUninitialized: false,
  cookie: {
    secure: false, // change to true if you're using HTTPS
    httpOnly: true,
    sameSite: "lax" // or "strict"
  }
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

app.get("/signup", (req, res) => {
  res.render("signup");
});


app.get('/feedback', (req, res) => {
  res.render('feedback'); // will render views/feedback.ejs
});

app.get('/facfeedback', (req, res) => {
  res.render('facfeedback'); // will render views/facfeedback.ejs
});

app.get('/chatbot', (req, res) => {
  const student_id = req.session.student_id || 'default_id'; // Fetch student_id from session or database
  res.render('chatbot', { student_id: student_id });
});


app.post("/verify-email", async (req, res) => {
  const { email } = req.body;

  try {
    const [rows] = await db.query("SELECT * FROM students WHERE email = ?", [email]);

    if (rows.length > 0) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      otpStore[email] = {
        otp,
        expiresAt: Date.now() + 5 * 60 * 1000  // OTP expires in 5 minutes
      };

      await sendOtpEmail(email, otp);

      res.json({ exists: true });
    } else {
      res.json({ exists: false });
    }
  } catch (error) {
    console.error("Database error during email verification:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/signup", async (req, res) => {
  const { email, otp } = req.body;

  const record = otpStore[email];
  if (!record || record.otp !== otp || Date.now() > record.expiresAt) {
    return res.status(400).json({ success: false, error: "Invalid or expired OTP" });
  }

  req.session.email = email;

  // ✅ OTP is valid — continue with registration logic here...
  delete otpStore[email];
  // Add your registration logic like storing user in DB here

  res.json({ success: true, redirectUrl: "/setprofile" });
  
});

app.get("/setprofile", (req, res) => {
  if (!req.session.email) {
    return res.redirect("/signup"); // or show unauthorized message
  }

  res.render("setprofile");
});

app.post("/set-profile", async (req, res) => {
  const { name, studentId, password } = req.body;
  const email = req.session.email; // assuming OTP/email verification stored this in session

  if (!email) {
    return res.status(401).json({ success: false, error: "Unauthorized access." });
  }
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      success: false,
      error: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
    });
  }

  try {
    // 1. Check if email exists in students table
    const [rows] = await db.query("SELECT * FROM students WHERE email = ?", [email]);

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: "Email not found in records." });
    }

    const student = rows[0];

    // 2. Match student_id from the database
    if (student.student_id !== studentId) {
      return res.status(400).json({
        success: false,
        error: "Please enter your correct student ID associated with this email.",
      });
    }

    // 3. Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Insert new user in student_login table
    await db.query(
      "INSERT INTO student_login (email, student_id, name, password) VALUES (?, ?, ?, ?)",
      [email, studentId, name, hashedPassword]
    );

    // 5. Redirect to student dashboard
    const token = jwt.sign({ email, studentId }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ success: true, redirectUrl: "/studentdash", token });

  } catch (error) {
    console.error("Error during signup:", error);

    // Handle duplicate email entry in student_login table
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ success: false, error: "Account already created for this email." });
    }

    res.status(500).json({ success: false, error: "Internal server error." });
  }
});

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

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password, role } = req.body;
  console.log("🔹 Login attempt:", { email, role });
  console.log(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD, process.env.COORDINATOR_EMAIL, process.env.COORDINATOR_PASSWORD)

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

    if (role.toLowerCase() === "student") {
      const { student_id } = req.body;
    
      if (!student_id) {
        return res.status(400).json({ error: "Student ID is required for student login." });
      }
    
      try {
        const [users] = await db.execute(
          "SELECT * FROM student_login WHERE email = ? AND student_id = ?",
          [email, student_id]
        );
    
        if (!users || users.length === 0) {
          return res.status(404).json({ error: "Invalid student credentials." });
        }
    
        const user = users[0];
    
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res.status(401).json({ error: "Invalid email or password." });
        }
    
        // Pass student_id in the token
        const token = jwt.sign(
          { email: user.email, role: user.role, student_id: user.student_id },
          process.env.SECRET_KEY,
          { expiresIn: "8h" }
        );
    
        res.clearCookie("auth_token");
        res.cookie("auth_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "Strict",
          maxAge: 8 * 60 * 60 * 1000,
        });
    
        return res.json({ token, role: user.role, redirectUrl: "/studentdash" });
      } catch (err) {
        console.error("❌ Student Login Error:", err);
        return res.status(500).json({ error: "Internal server error." });
      }
    }    

    // Faculty Login (e.g., Coordinator)
    if (role.toLowerCase() === "faculty") {
      let faculty;
      try {
        [faculty] = await db.execute("SELECT * FROM faculty_login WHERE email = ?", [email]);

        if (!faculty || faculty.length === 0) {
          console.error("❌ Faculty not found:", email);
          return res.status(404).json({ error: "Invalid email or password." });
        }

        const user = faculty[0];

        // Check if user password is valid
        if (!user.password) {
          console.error("❌ No password found for faculty:", email);
          return res.status(500).json({ error: "Internal server error." });
        }

        let passwordMatch;
        try {
          passwordMatch = await bcrypt.compare(password, user.password);
        } catch (bcryptError) {
          console.error("❌ Password comparison error:", bcryptError);
          return res.status(500).json({ error: "Password processing error. Try again." });
        }

        if (!passwordMatch) {
          console.error("❌ Incorrect password for faculty:", email);
          return res.status(401).json({ error: "Invalid email or password." });
        }

        return generateTokenAndRespond(res, user.email, user.role, "/faculty-dashboard");
      } catch (error) {
        console.error("❌ Faculty Login Error:", error);
        return res.status(500).json({ error: "Internal server error." });
      }
    }


    console.error("❌ Invalid role provided:", role);
    return res.status(400).json({ error: "Invalid role provided." });

  } catch (error) {
    console.error("❌ Login Error:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
});


// 📌 Routes
app.get('/coordinatordash', authenticateToken, async (req, res) => {
  if (req.user.role !== 'coordinator') {
    return res.redirect('/login');
  }

  try {
    // Fetch student count
    const [studentRows] = await db.execute("SELECT COUNT(*) AS count FROM students");
    const studentCount = studentRows[0].count || 0;

    // Fetch faculty count
    const [facultyRows] = await db.execute("SELECT COUNT(*) AS count FROM faculty");
    const facultyCount = facultyRows[0].count || 0;

    // Fetch mapping count
    const [mappingRows] = await db.execute("SELECT COUNT(*) AS count FROM faculty_student_mapping");
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

app.get('/studentdash', authenticateToken, (req, res) => {
  const studentId = req.user.student_id;
  console.log("📊 Student ID for dashboard:", studentId);

  // use studentId in your DB query to fetch dashboard data
  res.render("studentdash", { studentId });
});

async function getAverageTimeBySkill(studentId) {
  try {
    // Execute the query using db.query() which returns a promise
    const [rows] = await db.query(`
      SELECT skill_id, AVG(TIME_TO_SEC(totaltime)/60) AS avg_minutes
      FROM Results
      WHERE student_id = ? AND completed = 'Completed'
      GROUP BY skill_id
      ORDER BY skill_id
    `, [studentId]);

    return rows; // Return the result (rows)
  } catch (err) {
    console.error('Error querying database: ', err);
    throw err; // Rethrow error to handle it in the calling function
  }
}

app.get('/barchart', async (req, res) => {
  try {
    const studentId = req.user.student_id;
    const data = await getAverageTimeBySkill(studentId); // Await the result of the query

    const formatted = {
      skills: data.map(d => `Skill ${d.skill_id}`),
      avgTimes: data.map(d => {
        const avgMinutes = parseFloat(d.avg_minutes);
        return isNaN(avgMinutes) ? 0 : avgMinutes;
      })
  
    };

    res.render('barchart', {
      title: 'Student Skill Time Chart',
      chartHeading: 'Average Time per Question per Skill',
      chartData: formatted
    });
  } catch (err) {
    res.status(500).send('Error loading chart: ' + err.message);
  }
});

async function getCompletionStats(studentId) {
  try {
    const [totalStats] = await db.query(`
      SELECT 
        COUNT(CASE WHEN completed = 'Completed' THEN 1 END) AS total_completed,
        COUNT(CASE WHEN completed != 'Completed' THEN 1 END) AS total_not_completed
      FROM Results
      WHERE student_id = ?
    `, [studentId]);

    const [sessionStatsRaw] = await db.query(`
      SELECT session_no AS session,
             COUNT(CASE WHEN completed = 'Completed' THEN 1 END) AS completed,
             COUNT(CASE WHEN completed != 'Completed' THEN 1 END) AS not_completed
      FROM Results
      WHERE student_id = ?
      GROUP BY session_no
      ORDER BY session_no;
    `, [studentId]);

    // Always return 3 sessions (1, 2, 3) with 0s if missing
    const sessionStats = [1, 2, 3].map(no => {
      const found = sessionStatsRaw.find(s => s.session === no);
      return found || { session: no, completed: 0, not_completed: 0 };
    });

    const [skillStats] = await db.query(`
      SELECT skill_id,
             COUNT(CASE WHEN completed = 'Completed' THEN 1 END) AS completed,
             COUNT(CASE WHEN completed != 'Completed' THEN 1 END) AS not_completed
      FROM Results
      WHERE student_id = ?
      GROUP BY skill_id
      ORDER BY skill_id;
    `, [studentId]);

    return { totalStats, sessionStats, skillStats };
  } catch (err) {
    console.error('Error querying session data: ', err);
    throw err;
  }
}

app.get('/donut', async (req, res) => {
  try {
    const studentId = req.user.student_id;
    const data = await getCompletionStats(studentId); // calling the function to get the data

    res.render('donut', {
      title: 'Task Completion Overview',
      totalStats: data.totalStats,
      sessionStats: data.sessionStats,
      skillStats: data.skillStats // Make sure to pass skillStats here
    });
  } catch (err) {
    res.status(500).send('Error loading donut chart: ' + err.message);
  }
});

async function getTimeProgressionData(studentId) {
  try {
    const [rows] = await db.query(`
      SELECT skill_id, session_no, SUM(totaltime)/600 AS total_time
      FROM Results
      WHERE student_id = ?
      GROUP BY skill_id, session_no
      ORDER BY skill_id, session_no
    `, [studentId]);

    // Unique skill IDs on the x-axis
    const skills = [...new Set(rows.map(r => r.skill_id))];
    // Each line represents a different session number
    const sessions = [...new Set(rows.map(r => r.session_no))];
    const fixedColors = ['#F9CB9C', '	#B6D7A8', '#9AD3DA'];

    const chartData = sessions.map((session, index) => {
      return {
        label: `Session ${session}`,
        data: skills.map(skill => {
          const entry = rows.find(d => d.skill_id === skill && d.session_no === session);
          return entry ? entry.total_time : 0;
        }),
        borderColor: fixedColors[index % fixedColors.length],
        fill: false
      };
    });

    return { chartData, skills }; // Return the formatted chart data
  } catch (err) {
    console.error('Error fetching time progression data: ', err);
    throw err;
  }
}

app.get('/time-progression', async (req, res) => {
  try {
    const studentId = req.user.student_id;
    // Call the getTimeProgressionData function to fetch the chart data
    const timeProgressionData = await getTimeProgressionData();

    // Pass the data to the time-progression template
    res.render('time-progression', {
      chartData: timeProgressionData.chartData,
      skills: timeProgressionData.skills
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

const getAverageScore = async (studentId) => {
  const [rows] = await db.execute('SELECT AVG(totaltime)/100 AS averageScore FROM results WHERE student_id = ?', [studentId]);
  return rows[0].averageScore || 0;
};

const getTotalTimeSpent = async (studentId) => {
  const [rows] = await db.execute('SELECT SUM(totaltime)/100 AS totalTimeSpent FROM results WHERE student_id = ?', [studentId]);
  return rows[0].totalTimeSpent || 0;
};  
const getStudentRank = async (studentId) => {
  const [rows] = await db.execute(`
    SELECT student_id, AVG(totaltime)/100 AS averageScore
    FROM results
    GROUP BY student_id
    ORDER BY averageScore ASC
  `);
  const rank = rows.findIndex(row => row.student_id === studentId) + 1;
  return {
    rank,
    totalStudents: rows.length
  };
};
const getStudentPercentile = async (studentId) => {
  const [rows] = await db.execute(`
    SELECT student_id, AVG(totaltime)/100 AS averageScore
    FROM results
    GROUP BY student_id
    ORDER BY averageScore ASC
  `);

  const index = rows.findIndex(row => row.student_id === studentId);
  const percentile = Math.round(((rows.length - index - 1) / rows.length) * 100);

  return percentile; // e.g., 80 = top 20%
};

app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const studentId = req.user.student_id;
   
    const averageScore = await getAverageScore(studentId);
    const totalTimeSpent = await getTotalTimeSpent(studentId);
    const rankInfo = await getStudentRank(studentId);
const percentile = await getStudentPercentile(studentId);


    // Get the average time by skill
    const averageTimeData = await getAverageTimeBySkill(studentId);
    const formattedAverageTime = {
      skills: averageTimeData.map(d => `Skill ${d.skill_id}`),
      avgTimes: averageTimeData.map(d => {
        const avgMinutes = parseFloat(d.avg_minutes);
        return isNaN(avgMinutes) ? 0 : avgMinutes;
      })
    };

    // Get the completion stats
    const completionData = await getCompletionStats(studentId);

    // Get the time progression data
    const timeProgressionData = await getTimeProgressionData(studentId);

    // Ensure skillStats is passed
    const skills = completionData.skillStats; // Assuming this contains skill-specific data

    

    // Pass all data to the dashboard template
    res.render('dashboard', {
      title: 'Dashboard',
      chartHeading: 'Average Time per Question per Skill',
      chartData: formattedAverageTime, // Data for the bar chart
      totalStats: completionData.totalStats,
      sessionStats: completionData.sessionStats,
      skillStats: completionData.skillStats, // Data for the donut charts
      skills: skills, // Pass skills data for time progression chart
      timeProgressionChartData: timeProgressionData.chartData, // Data for time progression chart
      timeProgressionSkills: timeProgressionData.skills,
      averageScore:averageScore,
      totalTimeSpent,
      rankInfo,
  percentile
    });

  } catch (err) {
    res.status(500).send('Error loading dashboard: ' + err.message);
  }
});

app.get('/table', authenticateToken, async (req, res) => {
  try {
    const studentId = req.user.student_id;
    console.log("Student ID:", studentId);
    const [rows] = await db.query(`
  SELECT 
    r.student_id,
    r.faculty_id,
    r.skill_id,
    r.session_no,
    r.Qno,
    CAST(r.completed AS UNSIGNED) AS completed,
    r.totaltime,
    r.conducted_time,
    DATE_FORMAT(r.conducted_date, '%d-%b-%y') AS conducted_date,  -- Short format like 02-May-25
    s.skill_name,
    q.question
  FROM Results r
  JOIN skills s ON r.skill_id = s.skill_id
  LEFT JOIN evaluation_questions q ON r.skill_id = q.skill_id AND r.Qno = q.qno
  WHERE r.student_id = ?
  ORDER BY r.session_no, r.skill_id
`, [studentId]);
    console.log("Rows fetched:", rows);
    // Pass the fetched data to the EJS template
    res.render('table', { rows });
  } catch (err) {
    console.error("error", err.message);
    res.status(500).send('Server Error' +err.message);
  }
});

// NLP Function to Process User Input
function processInputWithNLP(userInput) {
  return new Promise((resolve, reject) => {
    exec(`python3 process_text.py "${userInput}"`, (error, stdout, stderr) => {
      if (error) {
        reject(`exec error: ${error}`);
        return;
      }
      resolve(stdout.trim());
    });
  });
}
app.post('/chatbot', (req, res) => {
  let originalMsg = req.body.message?.trim();

  if (!originalMsg) {
    return res.json({ reply: "I didn't receive any message." });
  }

  const normalizedMsg = normalizeMessage(originalMsg);
  console.log(`Normalized Message: ${normalizedMsg}`);

  // Check rule-based replies
  if (rules[normalizedMsg]) {
    return res.json({ reply: rules[normalizedMsg] });
  }

  try {
    // NLP-based entity extraction
    const doc = nlp(originalMsg);
    const skillEntities = doc.nouns().out('array');
    console.log(`Extracted Entities: ${JSON.stringify(skillEntities)}`);

    const allSkills = Object.keys(resources);

    // Try direct keyword matching if skill names appear in raw message
    const matchedSkill = allSkills.find(skill =>
      originalMsg.toLowerCase().includes(skill.toLowerCase()) ||
      skillEntities.some(entity => entity.toLowerCase().includes(skill.toLowerCase()))
    );

    console.log(`Matched Skill: ${matchedSkill}`);

    if (matchedSkill) {
      const skillResources = resources[matchedSkill] || [];
      const videoRecs = skillResources.filter(r => r.type === 'Video').slice(0, 2);
      const bookRecs = skillResources.filter(r => r.type === 'Book').slice(0, 2);

      if (videoRecs.length === 0 && bookRecs.length === 0) {
        return res.json({ reply: `Sorry, I couldn’t find any Video or Book resources for ${matchedSkill}.` });
      }

      let reply = `\`\`\`\nResources for ${matchedSkill}\n\n`;

      if (videoRecs.length > 0) {
        reply += `Videos:\n`;
        videoRecs.forEach((r, i) => {
          reply += `  ${i + 1}. ${r.resource}\n`;
        });
        reply += `\n`;
      }

      if (bookRecs.length > 0) {
        reply += `Books:\n`;
        bookRecs.forEach((r, i) => {
          reply += `  ${i + 1}. ${r.resource}\n`;
        });
      }

      reply += `\n\`\`\``;
      return res.json({ reply });
    }

    res.json({
      reply: "Sorry, I didn't quite understand that. You can ask about your skill performance or improvement suggestions."
    });
  } catch (error) {
    console.error("Error processing the message:", error);
    res.json({ reply: "Sorry, there was an error processing your request." });
  }
});

app.post('/evaluateResults', authenticateToken, async (req, res) => {
  try {
    const studentId = req.user.student_id;
    console.log("Student ID:", studentId);

    // Fetch results
    const [rows] = await db.query(`
      SELECT s.skill_name, r.skill_id, r.completed
      FROM results r
      JOIN skills s ON r.skill_id = s.skill_id
      WHERE r.student_id = ?
    `, [studentId]);

    console.log("Rows fetched:", rows); // Log rows to check for correct data

    if (rows.length === 0) {
      return res.json({ message: "No skill performance data found for the student.", performance: [] });
    }

    const skillData = {};

    // Tally up performance based on 'completed' field
    rows.forEach(row => {
      const status = row.completed.trim().toLowerCase(); // Normalize (lowercase and trim)
      if (!skillData[row.skill_name]) {
        skillData[row.skill_name] = { total: 0, successes: 0, failures: 0 };
      }
      skillData[row.skill_name].total += 1;
      if (status === "completed") {
        skillData[row.skill_name].successes += 1;
      } else if (status === "not completed") {
        skillData[row.skill_name].failures += 1;
      }
    });

    console.log("Skill data after tallying:", skillData); // Check if data is correct

    const performance = [];
    const recommendations = [];

    // Process the performance data
    for (const skill in skillData) {
      const { total, successes, failures } = skillData[skill];
      const successRate = total > 0 ? (successes / total) * 100 : 0;
      const failureRate = total > 0 ? (failures / total) * 100 : 0;

      performance.push({
        skill: skill,
        totalAttempts: total,
        successCount: successes,
        failureCount: failures,
        successRate: `${successRate.toFixed(2)}%`,
        failureRate: `${failureRate.toFixed(2)}%`,
        status: successRate < 50 ? "Needs Improvement" : "Good"
      });

      if (successRate < 50) {
        recommendations.push({
          skill: skill,
          message: `Your success rate in ${skill} is ${successRate.toFixed(2)}%. Consider more practice.`
        });
      }
    }

    const detailedReport = [];

    for (const skill in skillData) {
      const { total, successes, failures } = skillData[skill];
      const successRate = ((successes / total) * 100).toFixed(2);
      const failureRate = ((failures / total) * 100).toFixed(2);

      detailedReport.push({
        skill,
        totalAttempts: total,
        successes,
        failures,
        successRate: `${successRate}%`,
        failureRate: `${failureRate}%`,
      });
    }

    const message = recommendations.length > 0
      ? "Here are some skills you need to improve:"
      : "Great job! Here's a breakdown of your skill performance:";

    res.json({ message, detailedReport, recommendations });

  } catch (err) {
    console.error("❌ Error fetching student results:", err);
    res.status(500).json({ error: "An error occurred while fetching performance data." });
  }
});


// Helper function: Return 2 Videos + 2 Books from resources.json
async function getSkillRecommendations(skillName) {
  const all = resources[skillName] || [];
  const videos = all.filter(r => r.type === 'Video').slice(0, 2);
  const books = all.filter(r => r.type === 'Book').slice(0, 2);
  return [...videos, ...books];
}

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
    const [facultyStudentMapping] = await db.execute(`
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
    
    const [facultySkillMapping] = await db.execute(`
      SELECT 
        MIN(faculty_skill_mapping.id) AS id,
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
      await db.query(
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

// Update the existing /studentdata route to handle session filtering
app.get("/studentdata", authenticateToken, async (req, res) => {
  try {
    const username = req.user.email; // Extract faculty username from token

    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }

    const [facultyResult] = await db.query(
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
      let sessionFilter = "";
      let sessionParams = [facultyId, prn, skill];
      
      // Add session filter if provided
      if (req.query.session && req.query.session !== 'all') {
        sessionFilter = "AND r.session_no = ?";
        sessionParams.push(req.query.session);
      }
      
      const query = `
          SELECT 
              s.student_name,
              s.student_id, 
              sk.skill_name, 
              q.Question,
              r.session_no, 
              DATE_FORMAT(r.conducted_date, '%Y-%m-%d') AS conducted_date,
              r.totaltime,
              r.Qno,
              r.completed
          FROM results r
          JOIN skills sk ON r.skill_id = sk.skill_id
          JOIN students s ON r.student_id = s.student_id
          JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id  
          WHERE r.faculty_id = ? 
          AND s.student_id = ? 
          AND r.skill_id = ?
          ${sessionFilter}
          ORDER BY r.session_no DESC, r.Qno ASC;
      `;
      
      try {
        const [filteredResults] = await db.query(query, sessionParams);

        // Get session info if specific session is selected
        let sessionInfo = {};
        if (req.query.session && req.query.session !== 'all' && filteredResults.length > 0) {
          // Get session details
          const sessionQuery = `
            SELECT 
              DATE_FORMAT(conducted_date, '%Y-%m-%d') AS conducted_date,
              totaltime
            FROM results
            WHERE faculty_id = ?
            AND student_id = ?
            AND skill_id = ?
            AND session_no = ?
            LIMIT 1
          `;
          
          const [sessionData] = await db.query(
            sessionQuery, 
            [facultyId, prn, skill, req.query.session]
          );
          
          if (sessionData.length > 0) {
            sessionInfo = sessionData[0];
          }
        }

        return res.json({ filteredResults, sessionInfo });
      } catch (err) {
        console.error("Error fetching student data for PRN and skill:", err);
        return res.status(500).json({ error: "Error fetching data" });
      }
    }

    // Route to fetch sessions for a student and skill
app.get("/getStudentSessions", async (req, res) => {
  const { prn, skill } = req.query;
  try {
      const [sessions] = await db.query(`
          SELECT DISTINCT session_no, conducted_date
          FROM results
          WHERE student_id = ? AND skill_id = ?
          ORDER BY session_no
      `, [prn, skill]);
      res.json(sessions);
  } catch (error) {
      console.error("❌ Error fetching sessions:", error);
      res.status(500).json({ error: "Error fetching sessions" });
  }
});

    // If PRN or skill is missing, fetch available PRNs for selection
    const prnQuery = `SELECT DISTINCT student_id FROM results WHERE faculty_id = ?;`;
    try {
      const [prnRows] = await db.query(prnQuery, [facultyId]);
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
      const [facultyList] = await db.query("SELECT email FROM faculty");

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
              await db.query(
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

app.use('/videos', express.static(path.join(__dirname, 'videos')));

// 👇 The route remains mostly the same
app.get('/flashcards', authenticateToken, async (req, res) => {
  const studentId = req.user?.student_id;
  if (!studentId) {
    return res.status(400).send("Student ID not found.");
  }

  console.log("📌 Logged-in student ID:", studentId);

  try {
    const [flashcardData] = await db.query(`
      SELECT 
        r.skill_id,
        s.skill_name,
        r.session_no,
        r.Qno,
        q.Question
      FROM Results r
      JOIN skills s ON r.skill_id = s.skill_id
      JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id
      WHERE r.student_id = ? AND r.completed = 'Not Completed'
      ORDER BY r.skill_id, r.session_no
    `, [studentId]);

    console.log("📊 Flashcards fetched:", flashcardData);

    if (flashcardData.length === 0) {
      return res.render('flashcards', {
        flashcards: [],
        message: "🎉 No incorrect questions to review!"
      });
    }

    // Dynamically generate the video URL if video exists
    const flashcardsWithVideos = flashcardData.map((flashcard) => {
      const videoFilename = `${flashcard.skill_id}_${flashcard.Qno}.mp4`;
      const videoPath = path.join(__dirname, 'videos', videoFilename); // Not public anymore

      const videoExists = fs.existsSync(videoPath);
      const videoUrl = videoExists ? `/videos/${videoFilename}` : null;

      console.log(`🎥 Video for Skill ${flashcard.skill_id}, Qno ${flashcard.Qno}: ${videoExists ? 'FOUND' : 'NOT FOUND'}`);

      return {
        ...flashcard,
        videoUrl
      };
    });

    res.render('flashcards', {
      flashcards: flashcardsWithVideos,
      message: null
    });
  } catch (error) {
    console.error("❌ Error fetching flashcards:", error);
    res.status(500).send("Server error while fetching flashcards.");
  }
});

app.get('/getSkills', async (req, res) => {
  try {
      const [rows] = await db.query('SELECT DISTINCT skill_name FROM skills');

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
      const [facultyList] = await db.query(
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
      const [student] = await db.query("SELECT * FROM students WHERE student_id = ?", [student_id]);

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
        const [result] = await db.query(
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
      const [students] = await db.query(
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
      const [students] = await db.query(
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
      await db.query(
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
    await db.query('DELETE FROM faculty_student_mapping WHERE student_id = ?', [studentID]);

    // Now delete the student from the students table
    const [result] = await db.query('DELETE FROM students WHERE student_id = ?', [studentID]);

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
    await db.query(`DELETE FROM faculty_student_mapping WHERE student_id IN (${placeholders})`, student_ids);
    
    // Now, delete students from the students table
    await db.query(`DELETE FROM students WHERE student_id IN (${placeholders})`, student_ids);

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
    await db.query('DELETE FROM faculty_student_mapping');

    // Now, delete all students from the students table
    await db.query('DELETE FROM students');

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

    const [result] = await db.query(query, [values]);

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
      const [facultyList] = await db.query("SELECT faculty_id, email FROM faculty");

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
    const [facultyList] = await db.query(`
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
      const [faculty] = await db.query(
          "SELECT email FROM faculty WHERE faculty_id = ?", [faculty_id]
      );

      if (faculty.length === 0) {
          return res.status(404).json({ success: false, message: "❌ Faculty not found." });
      }

      const oldEmail = faculty[0].email;

      // 🔹 First update the faculty table
      const [result] = await db.query(
          "UPDATE faculty SET faculty_name = ?, department = ?, email = ? WHERE faculty_id = ?",
          [faculty_name, department, email, faculty_id]
      );

      // 🔹 Then update the faculty_login table
      await db.query(
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
      await db.query("DELETE FROM faculty_login WHERE email = ?", [email]);

      // Now delete from faculty
      const [result] = await db.query(
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
      await db.query("DELETE FROM faculty_student_mapping");
      await db.query("DELETE FROM faculty_skill_mapping");

      // Delete faculty login records (optional: if login records exist)
      await db.query("DELETE FROM faculty_login");

      // Now delete all faculty records
      const [result] = await db.query("DELETE FROM faculty");

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
    await db.query("DELETE FROM faculty_login WHERE email IN (?)", [emailList]);

    // Now delete from faculty
    const whereClause = selectedFaculty.map(() => "(email = ?)").join(" OR ");
    const values = selectedFaculty.flatMap(faculty => [faculty.email]);

    const [result] = await db.query(
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
      const [skills] = await db.query("SELECT skill_id, skill_name FROM skills");
      const studentId = req.query.student_id || null;
      const skillId = req.query.skill || null;
      const sessionNo = req.query.session || null;

      console.log("Query Parameters:", { studentId, skillId, sessionNo });

      let results = [];
      let sessionInfo = {};

      if (studentId && skillId) {
          let query = `
              SELECT 
                  s.student_id,
                  s.student_name, 
                  sk.skill_id,
                  sk.skill_name, 
                  q.Qno,
                  q.Question, 
                  r.completed AS status,
                  r.session_no,
                  r.totaltime,
                  r.conducted_date
              FROM results r
              JOIN skills sk ON r.skill_id = sk.skill_id
              JOIN students s ON r.student_id = s.student_id
              JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id
              WHERE s.student_id = ? AND sk.skill_id = ?
          `;
          let params = [studentId, skillId];

          if (sessionNo && sessionNo !== "all") {
              query += ` AND r.session_no = ?`;
              params.push(sessionNo);
          }

          console.log("Executing query:", query);
          console.log("With parameters:", params);

          [results] = await db.query(query, params);
          console.log("Query results:", results);

          if (sessionNo && sessionNo !== "all") {
              const [sessionData] = await db.query(`
                  SELECT session_no, conducted_date, totaltime
                  FROM results
                  WHERE student_id = ? AND skill_id = ? AND session_no = ?
                  LIMIT 1
              `, [studentId, skillId, sessionNo]);
              sessionInfo = sessionData[0] || {};
              console.log("Session info:", sessionInfo);
          }
      }

      res.json({ skills, results, sessionInfo });
  } catch (error) {
      console.error("❌ Error fetching results:", error);
      res.status(500).json({ error: "Error fetching results" });
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
    await db.query(`DELETE FROM students WHERE student_id IN (${placeholders})`, student_ids);
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
    await db.query('DELETE FROM faculty_student_mapping');

    // Then, delete all student records
    await db.query('DELETE FROM students');

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
    const [user] = await db.execute(
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
    await db.execute(
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
app.get("/forgotpassword", (req, res) => {
  res.render("forgotpassword"); // form with only email input
});
const studentOtpStore = {};
app.post("/forgotpassword", async (req, res) => {
  const { email } = req.body;

  try {
    const [rows] = await db.query("SELECT * FROM student_login WHERE email = ?", [email]);

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: "Email not found." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    studentOtpStore[email] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000 // 5 min
    };

    await sendOtpEmail(email, otp); // reuse your sendOtpEmail function
    req.session.studentEmail = email;

    res.json({ success: true, redirectUrl: "/verify-otp" });

  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ success: false, error: "Server error." });
  }
});
app.get("/verify-otp", (req, res) => {
  if (!req.session.studentEmail) return res.redirect("/forgotpassword");
  res.render("verify-otp"); // form to enter OTP
});
app.post("/verify-otp", (req, res) => {
  const { otp } = req.body;
  const email = req.session.studentEmail;

  const record = studentOtpStore[email];

  if (!record || record.otp !== otp || Date.now() > record.expiresAt) {
    return res.status(400).json({ success: false, error: "Invalid or expired OTP" });
  }

  delete studentOtpStore[email];
  req.session.verifiedForReset = true;

  res.json({ success: true, redirectUrl: "/reset-password" });
});
app.get("/reset-password", (req, res) => {
  if (!req.session.studentEmail || !req.session.verifiedForReset) {
    return res.redirect("/forgotpassword");
  }

  res.render("reset-password"); // form with new password + confirm password
});
app.post("/reset-password", async (req, res) => {
  const { newPassword } = req.body;
  const email = req.session.studentEmail;

  if (!email || !req.session.verifiedForReset) {
    return res.status(401).json({ success: false, error: "Unauthorized request." });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query("UPDATE student_login SET password = ? WHERE email = ?", [hashedPassword, email]);

    // Clear session flags
    delete req.session.studentEmail;
    delete req.session.verifiedForReset;

    res.json({ success: true });
  } catch (err) {
    console.error("Password reset error:", err);
    res.status(500).json({ success: false, error: "Server error." });
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
    const [facultyData] = await db.query(
      "SELECT faculty_id, faculty_name FROM faculty WHERE faculty_id IN (?)",
      [Array.from(facultyIds)]
    );
    const facultyMap = Object.fromEntries(facultyData.map(row => [row.faculty_id, row.faculty_name]));

    // 🔹 Fetch student names
    const [studentData] = await db.query(
      "SELECT student_id, student_name FROM students WHERE student_id IN (?)",
      [Array.from(studentIds)]
    );
    const studentMap = Object.fromEntries(studentData.map(row => [row.student_id, row.student_name]));

    
    let skillMap = {}; // Default empty object

    if (skillIds.size > 0) {  // Run query only if skillIds is not empty
        const [skillData] = await db.query(
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
      await db.query(
        "INSERT IGNORE INTO faculty_skill_mapping (faculty_id, skill_id) VALUES ?",
        [facultySkillInsertQueries]
      );
    }

    if (facultyStudentInsertQueries.length > 0) {
      await db.query(
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
      const [rows] = await db.execute(`
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

    const [facultyResult] = await db.query(
      `SELECT faculty_id FROM faculty WHERE email = ?`,
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id; // Extract faculty_id

    
    const [skills] = await db.query(
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
    const [facultyResult] = await db.query(
      `SELECT faculty_id FROM faculty WHERE email = ?`,
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id; // Extract faculty_id

    // Fetch students mapped to this faculty for the selected skill
    const [students] = await db.query(
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
    const [rows] = await db.execute(
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


    const [facultyResult] = await db.query(
      `SELECT faculty_id FROM faculty WHERE email = ?`, 
      [username]
    );

    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const faculty_id = facultyResult[0].faculty_id; // Extract faculty_id

    for (const result of results) {
      const { student_id, skill_id, Qno,session_no, Result, totaltime, conducted_time, conducted_date } = result;

      const query = `
        INSERT INTO Results (student_id, faculty_id, skill_id, session_no, Qno, totaltime, conducted_time, completed, conducted_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)
      `;
      await db.query(query, [student_id, faculty_id, skill_id, session_no, Qno, totaltime, conducted_time, Result, conducted_date]);
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
      const [existingStudent] = await db.query(
          "SELECT * FROM results WHERE student_id = ? AND conducted_date = ?;",
          [prn, conductedDate]
      );

      if (existingStudent.length === 0) {
          return res.status(404).json({ message: "Student data not found" });
      }

      for (const answer of updatedAnswers) {
          await db.query(
              "UPDATE results SET Result = ? WHERE student_id = ? AND qno = ? AND conducted_date = ?;",
              [answer.result, prn, answer.qno, conductedDate]
          );
      }

      if (totaltime && typeof totaltime[conductedDate] !== "undefined") {
          const totalTimeValue = totaltime[conductedDate];

          await db.query(
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
        const [rows] = await db.query('SELECT MAX(skill_id) AS max_id FROM skills');
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

        await db.query('INSERT INTO skills (skill_id, skill_name) VALUES (?, ?)', [skillId, skillName]);

        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheetData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        for (let row of sheetData) {
            if (row.Qno && row.Question) {
                await db.query(
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
    const [rows] = await db.query("SELECT * FROM skills");
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
    const [rows] = await db.query(
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
    const [result] = await db.query(
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
    const [result] = await db.query(
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
    const [result] = await db.query(
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

const HOD_EMAIL = process.env.EMAIL_USER;
const HOD_PASSWORD = process.env.EMAIL_PASS;

app.post('/send-feedback', async (req, res) => {
  try {
    const responses = {
      strengths: [],
      challenges: [],
      suggestions: []
    };

    // Fetch and parse the CSV
    await axios.get(csvUrl, { responseType: "stream" })
      .then(res => {
        return new Promise((resolve, reject) => {
          res.data
            .pipe(csv())
            .pipe(new Writable({
              objectMode: true,
              write(row, encoding, callback) {
                if (row['What were your strengths as a participant in the simulation lab? Please provide specific examples.']) {
                  responses.strengths.push(row['What were your strengths as a participant in the simulation lab? Please provide specific examples.']);
                }
                if (row['What challenges did you face in simulation session? Please elaborate in detail.']) {
                  responses.challenges.push(row['What challenges did you face in simulation session? Please elaborate in detail.']);
                }
                if (row['What suggestions do you have for improving future simulation sessions? Please share any ideas you think would enhance the learning experience.']) {
                  responses.suggestions.push(row['What suggestions do you have for improving future simulation sessions? Please share any ideas you think would enhance the learning experience.']);
                }
                callback();
              },
              final(callback) {
                resolve();
                callback();
              }
            }));
        });
      });

    if (responses.strengths.length === 0 && responses.challenges.length === 0 && responses.suggestions.length === 0) {
      console.log('No data found in the specified columns');
      return res.status(400).json({ success: false, message: 'No data found' });
    }

    // Python summarization call
    const summarizeWithPython = (responses) => {
      return new Promise((resolve, reject) => {
        const pythonProcess = spawn('python3', [path.join(__dirname, 'summarizer.py')]);
        let output = '';

        pythonProcess.stdout.on('data', (data) => {
          output += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
          console.error("Python error:", data.toString());
        });

        pythonProcess.on('close', (code) => {
          if (code !== 0) return reject(new Error("Python summarizer failed"));
          try {
            const parsed = JSON.parse(output);
            resolve(parsed);
          } catch (e) {
            reject(new Error("Failed to parse summary JSON"));
          }
        });

        pythonProcess.stdin.write(JSON.stringify(responses));
        pythonProcess.stdin.end();
      });
    };

    const summaryData = await summarizeWithPython(responses);

    const summary = `
    Daily Summary of Simulation Lab Responses:

    🟢 Strengths:
    ${summaryData.strengths}

    🟡 Challenges Faced:
    ${summaryData.challenges}

    🔵 Suggestions for Improvement:
    ${summaryData.suggestions}
    `;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: HOD_EMAIL,
        pass: HOD_PASSWORD
      }
    });

    const mailOptions = {
      from: HOD_EMAIL,
      to: "gvithalani9@gmail.com",
      subject: "Daily Summary of Simulation Lab Responses",
      text: summary
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("❌ Email error:", err);
        return res.status(500).json({ success: false, message: 'Email error' });
      } else {
        console.log("✅ Daily summary email sent:", info.response);
        return res.status(200).json({ success: true, message: 'Feedback sent successfully' });
      }
    });

  } catch (err) {
    console.error("❌ Error in send-feedback:", err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/send-faculty-feedback', async (req, res) => {
  try {
    const feedback = {
      positives: [],
      concerns: [],
      recommendations: []
    };

    await axios.get(facultyCsvUrl, { responseType: 'stream' })
      .then(response => {
        return new Promise((resolve, reject) => {
          response.data
            .pipe(csv())
            .pipe(new Writable({
              objectMode: true,
              write(row, encoding, callback) {
                if (row['What do you feel were your strengths in the simulation lab?']) {
                  feedback.positives.push(row['What do you feel were your strengths in the simulation lab?']);
                }
                if (row['What were the challenges in today’s simulation session?']) {
                  feedback.concerns.push(row['What were the challenges in today’s simulation session?']);
                }
                if (row['Please describe any professional development needs you identified for yourself based on the performance.']) {
                  feedback.recommendations.push(row['Please describe any professional development needs you identified for yourself based on the performance.']);
                }                
                callback();
              },
              final(callback) {
                resolve();
                callback();
              }
            }));
        });
      });

    if (feedback.positives.length === 0 && feedback.concerns.length === 0 && feedback.recommendations.length === 0) {
      return res.status(400).json({ success: false, message: 'No feedback data found' });
    }

    const summarizeWithPython = (feedback) => {
      return new Promise((resolve, reject) => {
        const pythonProcess = spawn('python3', [path.join(__dirname, 'summarizer.py')]);
        let output = '';

        pythonProcess.stdout.on('data', (data) => {
          output += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
          console.error("Python error:", data.toString());
        });

        pythonProcess.on('close', (code) => {
          if (code !== 0) return reject(new Error("Python summarizer failed"));
          try {
            resolve(JSON.parse(output));
          } catch {
            reject(new Error("Failed to parse summary JSON"));
          }
        });

        pythonProcess.stdin.write(JSON.stringify(feedback));
        pythonProcess.stdin.end();
      });
    };

    const summaryData = await summarizeWithPython(feedback);

    const summary = `
📋 Faculty Feedback Summary:

✅ What Went Well:
${summaryData.positives}

⚠️ Observed Concerns:
${summaryData.concerns}

💡 Suggestions for Future:
${summaryData.recommendations}
`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: HOD_EMAIL,
        pass: HOD_PASSWORD
      }
    });

    const mailOptions = {
      from: HOD_EMAIL,
      to: "gvithalani9@gmail.com",
      subject: "Faculty Feedback Summary - Simulation Session",
      text: summary
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("Email error:", err);
        return res.status(500).json({ success: false, message: 'Email send failed' });
      } else {
        console.log("Faculty summary email sent:", info.response);
        return res.status(200).json({ success: true, message: 'Faculty feedback sent successfully' });
      }
    });

  } catch (err) {
    console.error("Error in /send-faculty-feedback:", err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
async function getFacultyIdByEmail(email) {
  try {
    const [rows] = await db.query(
      'SELECT faculty_id FROM Faculty WHERE email = ?',
      [email]
    );
    return rows.length > 0 ? rows[0].faculty_id : null;
  } catch (err) {
    console.error('Error fetching faculty_id: ', err);
    throw err;
  }
}

async function getCompletionRateBySkill(facultyId) {
  try {
    const [rows] = await db.query(`
      SELECT skill_id,
        ROUND(SUM(CASE WHEN completed = 'Completed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) AS completion_percentage
      FROM Results
      WHERE faculty_id = ?
      GROUP BY skill_id
      ORDER BY skill_id
    `, [facultyId]);

    return rows;
  } catch (err) {
    console.error('Error fetching completion rate: ', err);
    throw err;
  }
}

app.get('/faculty/barchart', authenticateToken,async (req, res) => {
  try {
    const facultyEmail = req.user.email; // From JWT

    const facultyId = await getFacultyIdByEmail(facultyEmail);
    if (!facultyId) {
      return res.status(404).send('Faculty not found.');
    }

    const data = await getCompletionRateBySkill(facultyId);

    const formatted = {
      skills: data.map(d => `Skill ${d.skill_id}`),
      completionRates: data.map(d => {
        const pct = parseFloat(d.completion_percentage);
        return isNaN(pct) ? 0 : pct;
      })
    };

    res.render('facultyBar', {
      title: 'Faculty Skill Completion Chart',
      chartHeading: 'Skill-wise Completion %',
      chartData: formatted
    });
  } catch (err) {
    res.status(500).send('Error loading faculty chart: ' + err.message);
  }
});


async function getFacultyTimeProgressionData(facultyId) {
  try {
    const [rows] = await db.query(`
      SELECT skill_id, session_no, SUM(totaltime)/600 AS total_time
      FROM Results
      WHERE faculty_id = ? 
      GROUP BY skill_id, session_no
      ORDER BY skill_id, session_no
    `, [facultyId]);
    console.log("✅ Query results:", rows);

    // Unique skill IDs on the x-axis
    const skills = [...new Set(rows.map(r => r.skill_id))];
    // Each line represents a different session number
    const sessions = [...new Set(rows.map(r => r.session_no))];
    console.log("✅ Skills:", skills);
    console.log("✅ Sessions:", sessions);
    const fixedColors = ['#F9CB9C', '#B6D7A8', '#9AD3DA'];

    const chartData = sessions.map((session, index) => {
      return {
        label: `Session ${session}`,
        data: skills.map(skill => {
          const entry = rows.find(d => d.skill_id === skill && d.session_no === session);
          return entry ? entry.total_time : 0;
        }),
        borderColor: fixedColors[index % fixedColors.length],
        fill: false
      };
    });

    return { chartData, skills }; // Return the formatted chart data
  } catch (err) {
    console.error('Error fetching faculty time progression data: ', err);
    throw err;
  }
}

app.get('/faculty/time-progression', authenticateToken, async (req, res) => {
  try {
    const facultyEmail = req.user.email;
    const facultyId = await getFacultyIdByEmail(facultyEmail);
    if (!facultyId) {
      return res.status(404).send('Faculty not found.');
    }

    // Call the getFacultyTimeProgressionData function to fetch the chart data
    const timeProgressionData = await getFacultyTimeProgressionData(facultyId);

    // Pass the data to the faculty time-progression template
    res.render('faculty-time-progression', {
      chartData: timeProgressionData.chartData,
      skills: timeProgressionData.skills
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Helper function to convert time string (HH:MM:SS) to seconds
function convertToSeconds(timeStr) {
  console.log("Converting time:", timeStr); // Log to check timeStr

  // Ensure the time string is valid
  if (typeof timeStr !== 'string' || !timeStr.includes(':')) {
    console.error("Invalid time format:", timeStr);
    return 0; // Return 0 if invalid
  }

  const [hours, minutes, seconds] = timeStr.split(':').map(Number);

  // Check if hours, minutes, and seconds are valid numbers
  if (isNaN(hours) || isNaN(minutes) || isNaN(seconds)) {
    console.error("Invalid time value:", timeStr);
    return 0; // Return 0 if the time value is invalid
  }

  return hours * 3600 + minutes * 60 + seconds;
}
async function getTimeTakenBySkill(facultyId) {
  try {
    const [rows] = await db.query(`
      SELECT skill_id, totaltime
      FROM Results
      WHERE faculty_id = ?
      ORDER BY skill_id
    `, [facultyId]);
    console.log('Query results:', rows);

    // Group by skill_id and gather all valid times for that skill
    const skills = rows.reduce((acc, row) => {
      if (row.totaltime) {
        // Assuming you have a convertToSeconds function to validate the time
        const seconds = convertToSeconds(row.totaltime);  // Make sure this function is defined
        if (seconds > 0) {
          if (!acc[row.skill_id]) acc[row.skill_id] = [];
          acc[row.skill_id].push(seconds); // Store the valid time in seconds
        } else {
          console.error("Invalid time format for skill_id:", row.skill_id, "totaltime:", row.totaltime);
        }
      } else {
        console.error("Missing totaltime for skill_id:", row.skill_id);
      }
      return acc;
    }, {});

    console.log("✅ Skills:", skills);  // Log grouped skills data

    // Ensure skills are populated correctly before returning
    if (Object.keys(skills).length === 0) {
      console.error("No valid data found for skills.");
    }

    // Convert grouped data into an array of skills with their times (in seconds)
    const skillsData = Object.keys(skills).map(skillId => ({
      skill_id: skillId,
      times: skills[skillId]
    }));

    console.log("Formatted Data for Chart:", skillsData);

    return skillsData;

  } catch (err) {
    console.error('Error fetching time data:', err);
    throw err;
  }
}
app.get('/faculty/boxplot', authenticateToken, async (req, res) => {
  try {
    const facultyEmail = req.user.email; // Get faculty email from JWT
    const facultyId = await getFacultyIdByEmail(facultyEmail);
    
    if (!facultyId) {
      return res.status(404).send('Faculty not found.');
    }
    console.log("faculty id:", facultyId);

    // Fetch data for the box plot (time taken per skill)
    const data = await getTimeTakenBySkill(facultyId); // Custom function to fetch the time data per skill
    
    console.log("Raw Data:", data); // Log raw data

    const formattedData = data.map(record => ({
      skillId: record.skill_id,
      times: record.times
    }));
    

    console.log("Formatted Data for Chart:", formattedData); // Log formatted data for chart

    // Pass the data to the EJS template
    res.render('facultyBoxPlot', {
      title: 'Faculty Skill Time Box Plot',
      chartHeading: 'Time Distribution Across Skills',
      chartData: formattedData
    });
  } catch (err) {
    console.error('Error loading faculty box plot:', err);
    res.status(500).send('Server Error');
  }
});

const totalStudentsEvaluated = async (faculty_id) => {
  const [rows] = await db.execute('SELECT COUNT(DISTINCT student_id) AS totalStudents FROM results WHERE faculty_id = ?', [faculty_id]);
  return rows[0].totalStudents || 0;
};
const totalSkillsEvaluated = async (faculty_id) => {
  const [rows] = await db.execute('SELECT COUNT(DISTINCT skill_id) AS totalSkills FROM results WHERE faculty_id = ?', [faculty_id]);
  return rows[0].totalSkills || 0;
};
const averageCompletionRate = async (faculty_id) => {
  const [rows] = await db.execute(`
    SELECT 
      AVG(completed_sessions / total_sessions) * 100 AS averageCompletionRate 
    FROM 
      (SELECT 
         skill_id,
         COUNT(CASE WHEN totaltime > 0 THEN 1 END) AS completed_sessions,
         COUNT(session_no) AS total_sessions
       FROM 
         results 
       WHERE 
         faculty_id = ?
       GROUP BY 
         skill_id) AS completion_data
  `, [faculty_id]);

  return rows[0].averageCompletionRate || 0;
};
const averageTimeTaken = async (faculty_id) => {
  const [rows] = await db.execute(`
    SELECT 
      AVG(totaltime) / 60 AS averageTimeTaken
    FROM 
      results
    WHERE 
      faculty_id = ? AND totaltime > 0
  `, [faculty_id]);

  return rows[0].averageTimeTaken || 0;
};
app.get('/faculty/dashboard', authenticateToken, async (req, res) => {
  try {
    const facultyEmail = req.user.email;
    const facultyId = await getFacultyIdByEmail(facultyEmail);
    if (!facultyId) {
      return res.status(404).send('Faculty not found.');
    }

    // Fetching the skill session data
    const query = `SELECT skill_id, session_no, totaltime FROM Results WHERE faculty_id = ?`;
    const [rawResults] = await db.query(query, [facultyId]);

    if (!rawResults || rawResults.length === 0) {
      return res.status(404).send('No skill session data found.');
    }

    const rawData = rawResults;
    const formattedData = [];

    for (let row of rawData) {
      const { skill_id, session_no, totaltime } = row;

      if (!skill_id || !totaltime || totaltime === '00:00:00') continue;

      const [hh, mm, ss] = totaltime.split(':').map(Number);
      const totalTimeInHours = (hh * 60 + mm + ss / 60) / 60;

      formattedData.push({
        skill_id,
        session_no,
        total_time: totalTimeInHours.toFixed(4),
      });
    }

    // Fetching completion rate and time progression data
    let completionRate = await getCompletionRateBySkill(facultyId);
    const timeProgression = await getFacultyTimeProgressionData(facultyId);
    completionRate = completionRate.map(item => ({
      ...item,
      rate: parseFloat(item.rate).toFixed(2)
    }));
    
    // Fetching the KPIs
    const totalStudents = await totalStudentsEvaluated(facultyId);
    const totalSkills = await totalSkillsEvaluated(facultyId);
    const avgCompletionRate = parseFloat(await averageCompletionRate(facultyId)).toFixed(2);
    const avgTimeTaken = parseFloat(await averageTimeTaken(facultyId)).toFixed(2);


    // Send the data to the dashboard page
    res.render('facultyvisual', {
      title: 'Faculty Dashboard',
      chartHeading: 'Faculty Dashboard - Skill Performance',
      completionRate: JSON.stringify(completionRate),
      timeProgression: JSON.stringify(timeProgression.chartData), 
      chartData: JSON.stringify(formattedData),
      skills: JSON.stringify(timeProgression.skills),
      totalStudents,
      totalSkills,
      avgCompletionRate,
      avgTimeTaken,
    });

  } catch (err) {
    res.status(500).send('Error loading dashboard: ' + err.message);
  }
});

app.get('/faculty/time-progression', authenticateToken, async (req, res) => {
  try {
    const facultyEmail = req.user.email;
    const facultyId = await getFacultyIdByEmail(facultyEmail);
    if (!facultyId) {
      return res.status(404).send('Faculty not found.');
    }

    // Call the getFacultyTimeProgressionData function to fetch the chart data
    const timeProgressionData = await getFacultyTimeProgressionData(facultyId);

    // Pass the data to the faculty time-progression template
    res.render('faculty-time-progression', {
      chartData: timeProgressionData.chartData,
      skills: timeProgressionData.skills
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// BACKEND ROUTE MODIFICATION
app.get('/facultyanalysis', authenticateToken, async (req, res) => {
  try {
    const username = req.user.email;
    if (!username) {
      return res.status(400).json({ error: "Username missing from token" });
    }

    // Query to fetch faculty details
    const [facultyResult] = await db.query(
      `SELECT faculty_id, faculty_name FROM faculty WHERE email = ?`,
      [username]
    );
    
    if (facultyResult.length === 0) {
      return res.status(404).json({ error: "Faculty not found" });
    }

    const facultyId = facultyResult[0].faculty_id;

    // Query to fetch mapped skills for faculty - MODIFIED to ensure uniqueness
    const [skillMap] = await db.query(
      `SELECT DISTINCT fsm.skill_id, sk.skill_name 
       FROM faculty_skill_mapping fsm 
       JOIN skills sk ON fsm.skill_id = sk.skill_id 
       WHERE fsm.faculty_id = ?`,
      [facultyId]
    );
    
    if (skillMap.length === 0) {
      return res.status(404).json({ error: "No skills mapped to this faculty" });
    }
    
    const allSkillsData = [];
    let excellent = 0, good = 0, average = 0, poor = 0;

    // Loop through skills and get performance data
    for (const skill of skillMap) {
      const skillId = skill.skill_id;

      const [performanceResults] = await db.query(
        `SELECT s.student_name, ROUND((MAX(r.completed) / MAX(r.totaltime)) * 100, 2) AS completion_rate
         FROM results r
         JOIN students s ON r.student_id = s.student_id
         WHERE r.faculty_id = ? AND r.skill_id = ? AND r.totaltime > 0
         GROUP BY s.student_id`,
        [facultyId, skillId]
      );
      

      // Performance bucket classification
      performanceResults.forEach(({ completion_rate }) => {
        const rate = parseFloat(completion_rate);
        if (rate >= 76) excellent++;
        else if (rate >= 51) good++;
        else if (rate >= 26) average++;
        else poor++;
      });

      allSkillsData.push({
        skillId: skillId,
        skillName: skill.skill_name,
        studentNames: performanceResults.map(r => r.student_name),
        studentScores: performanceResults.map(r => r.completion_rate)
      });
    }

    // Calculate average total time per student for the first skill
    const firstSkillId = skillMap[0].skill_id;

    const [timeResults] = await db.query(
      `SELECT s.student_name, AVG(r.totaltime) AS averagetime
       FROM students s
       JOIN faculty_student_mapping fsm ON s.student_id = fsm.student_id
       JOIN results r ON s.student_id = r.student_id
         AND r.faculty_id = fsm.faculty_id AND r.skill_id = fsm.skill_id
       WHERE fsm.faculty_id = ? AND fsm.skill_id = ?
       GROUP BY s.student_name`,
      [facultyId, firstSkillId]
    );

    const studentNames = timeResults.map(row => row.student_name);
    const studentScores = timeResults.map(row => {
      const avg = parseFloat(row.averagetime);
      return isNaN(avg) ? 0 : Number(avg.toFixed(2));
    });

    // Time distribution data for box plot
    const boxPlotData = await getTimeTakenBySkill(facultyId); // Assumed utility function
    const chartData = boxPlotData.map(record => ({
      skillId: record.skill_id,
      times: record.times
    }));

    // Fetching KPIs for the faculty
    const totalStudents = await totalStudentsEvaluated(facultyId);
    const totalSkills = await totalSkillsEvaluated(facultyId);
    const avgCompletionRate = await averageCompletionRate(facultyId);
    const avgTimeTaken = await averageTimeTaken(facultyId);

    // Send the data to the 'facultyanalysis' page
    res.render('facultyanalysis', {
      excellent,
      good,
      average,
      poor,
      studentNames,
      studentScores,
      facultyName: facultyResult[0].faculty_name,
      skillName: skillMap[0].skill_name,
      chartHeading: 'Time Distribution Across Skills',
      chartData,
      totalStudents,
      totalSkills,
      avgCompletionRate,
      avgTimeTaken,
      allSkillsData
    });

  } catch (err) {
    console.error("Error in /facultyanalysis:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/viewresult", authenticateToken, async (req, res) => {
  try {
    const [prnRows] = await db.query("SELECT DISTINCT student_id FROM results");
    const [skills] = await db.query("SELECT skill_id, skill_name FROM skills");
    const availablePRNs = prnRows.map((row) => row.student_id);

    res.render("viewresult", {
      studentIdList: availablePRNs,
      studentId: null,
      skills,
      results: [],
    });
  } catch (error) {
    console.error("Unexpected error in GET /viewresult:", error);
    res.status(500).send("Internal server error");
  }
});

app.get("/viewresult/data", authenticateToken, async (req, res) => {
  const studentId = req.query.student_id;

  if (!studentId) {
    return res.status(400).json({ error: "student_id is required" });
  }

  try {
    const query = `
      SELECT 
        s.student_name,
        sk.skill_name,
        q.Question,
        r.completed AS Result,
        r.session_no,
        DATE_FORMAT(r.conducted_date, '%Y-%m-%d') AS conducted_date
      FROM results r
      JOIN skills sk ON r.skill_id = sk.skill_id
      JOIN students s ON r.student_id = s.student_id
      JOIN evaluation_questions q ON r.Qno = q.Qno AND r.skill_id = q.skill_id
      WHERE r.student_id = ?
      ORDER BY r.session_no DESC, r.Qno ASC;
    `;

    const [fetchedResults] = await db.query(query, [studentId]);

    // Group results by session
    const groupedBySession = {};
    fetchedResults.forEach(row => {
      const sessionKey = `Session ${row.session_no} - ${row.conducted_date}`;
      if (!groupedBySession[sessionKey]) {
        groupedBySession[sessionKey] = [];
      }
      groupedBySession[sessionKey].push(row);
    });

    res.json({ groupedResults: groupedBySession });
  } catch (error) {
    console.error("Unexpected error in GET /viewresult/data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// 📌 Start Server
app.listen(3000, () => console.log("🚀 Server running on port 3000"));