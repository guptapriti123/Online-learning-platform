const express = require('express');
const cors = require('cors');
const bdypar = require('body-parser');
const mysq = require('mysql2');
const bcrypt = require('bcryptjs');  
const jwt = require('jsonwebtoken');  
const server1 = express();

// Middlewares
server1.use(cors());
server1.use(express.json());

//Database Connectivity
const db = mysq.createConnection({
  host:'localhost',
  user:'root',
  password: 'root',
  database:'learning',
  port:3306
})

db.connect((error)=>{
   if(error){
    console.log("Fail to connect");
   }
   else{
    console.log("Successfully Connected To Database");
   }
});

// Start Server - PORT 8080
server1.listen(8080, function check(error) {  
  if (error) {
    console.log(" Error starting server");
  } else {
    console.log(" Server Started on port : 8080");
  }
});

//register
server1.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // check if any field is empty
    if (!name || !email || !password) {
      return res.status(400).json({ 
        status: false, 
        message: "All fields are required" 
      });
    }

    // Check if user already exists
    const checkQuery = `SELECT * FROM users WHERE email = ?`;
    db.query(checkQuery, [email], async (error, result) => {
      if (error) {
        console.log("Database error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Database error" 
        });
      }

      if (result.length > 0) {
        return res.status(400).json({ 
          status: false, 
          message: "Email already exists" 
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user with default role
      const insertQuery = `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'user')`;
      db.query(insertQuery, [name, email, hashedPassword], (error, result) => {
        if (error) {
          console.log("Insert error:", error);
          return res.status(500).json({ 
            status: false, 
            message: "Registration failed" 
          });
        }

        // Generate JWT token
        const token = jwt.sign(
          { 
            id: result.insertId, 
            name: name, 
            email: email,
            role: 'user'
          },
          'supersecretkey',
          { expiresIn: '1d' }
        );

        res.status(201).json({
          status: true,
          message: "Registration successful",
          token: token,
          id: result.insertId,
          name: name,
          email: email,
          role: 'user'
        });
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== LOGIN ====================
server1.post("/api/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        status: false, 
        message: "Email and password are required" 
      });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    db.query(query, [email], async (error, result) => {
      if (error) {
        console.log("Database error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Database error" 
        });
      }

      if (result.length === 0) {
        return res.status(401).json({ 
          status: false, 
          message: "Invalid email or password" 
        });
      }

      const user = result[0];

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ 
          status: false, 
          message: "Invalid email or password" 
        });
      }

      const token = jwt.sign(
        { 
          id: user.id, 
          name: user.name, 
          email: user.email,
          role: user.role || 'user' 
        },
        'supersecretkey',
        { expiresIn: '1d' }
      );

      res.status(200).json({
        status: true,
        message: "Login successful",
        token: token,
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user'  
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== UPDATE PROFILE ====================
server1.put("/api/auth/user/profile", async (req, res) => 
{
  console.log(" Update profile endpoint hit!"); // Debug log
  
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "No token provided" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }

    const userId = decoded.id;

    const { name, email, currentPassword, newPassword } = req.body;

    if (!name || !email) {
      return res.status(400).json({ 
        status: false, 
        message: "Name and email are required" 
      });
    }

    const getUserQuery = `SELECT * FROM users WHERE id = ?`;
    db.query(getUserQuery, [userId], async (error, result) => {
      if (error) {
        console.log("Database error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Database error" 
        });
      }

      if (result.length === 0) {
        return res.status(404).json({ 
          status: false, 
          message: "User not found" 
        });
      }

      const user = result[0];

      let hashedPassword = user.password;
      if (newPassword) {
        if (!currentPassword) {
          return res.status(400).json({ 
            status: false, 
            message: "Current password is required" 
          });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          return res.status(401).json({ 
            status: false, 
            message: "Current password is incorrect" 
          });
        }

        hashedPassword = await bcrypt.hash(newPassword, 10);
      }

      const updateQuery = `UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?`;
      db.query(updateQuery, [name, email, hashedPassword, userId], (error, result) => {
        if (error) {
          console.log("Update error:", error);
          return res.status(500).json({ 
            status: false, 
            message: "Update failed" 
          });
        }

        res.status(200).json({
          status: true,
          message: "Profile updated successfully",
          name: name,
          email: email
        });
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== GET ALL COURSES ====================
server1.get("/api/courses", (req, res) => {
  const query = `SELECT * FROM courses ORDER BY created_at DESC`;
  
  db.query(query, (error, results) => {
    if (error) {
      console.log("Database error:", error);
      return res.status(500).json({ 
        status: false, 
        message: "Failed to fetch courses" 
      });
    }

    res.status(200).json({
      status: true,
      data: results
    });
  });
});

// ==================== GET SINGLE COURSE ====================
server1.get("/api/courses/:id", (req, res) => {
  const courseId = req.params.id;
  const query = `SELECT * FROM courses WHERE id = ?`;
  
  db.query(query, [courseId], (error, results) => {
    if (error) {
      return res.status(500).json({ 
        status: false, 
        message: "Database error" 
      });
    }

    if (results.length === 0) {
      return res.status(404).json({ 
        status: false, 
        message: "Course not found" 
      });
    }

    res.status(200).json({
      status: true,
      data: results[0]
    });
  });
});

// ==================== ADD COURSE (Admin Only) - UPDATED WITHOUT PRICE & IMAGE ====================
server1.post("/api/courses", (req, res) => {
  console.log("=== ADD COURSE ENDPOINT HIT ===");
  console.log("Request body:", req.body);
  
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
      console.log("Decoded token:", decoded);
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    // Check if user is admin
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const { title, description, instructor, duration } = req.body;

    if (!title || !description) {
      return res.status(400).json({ 
        status: false, 
        message: "Title and description are required" 
      });
    }

    // UPDATED QUERY - WITHOUT PRICE AND IMAGE_URL
    const query = `INSERT INTO courses (title, description, instructor, duration) 
                   VALUES (?, ?, ?, ?)`;
    
    console.log("Executing query:", query);
    console.log("With values:", [title, description, instructor || '', duration || '']);
    
    db.query(query, [title, description, instructor || '', duration || ''], (error, result) => {
      if (error) {
        console.log("=== INSERT ERROR ===");
        console.log("Error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to add course",
          error: error.message
        });
      }

      console.log("=== COURSE ADDED SUCCESSFULLY ===");
      console.log("Insert ID:", result.insertId);
      
      res.status(201).json({
        status: true,
        message: "Course added successfully",
        data: {
          id: result.insertId,
          title,
          description,
          instructor: instructor || '',
          duration: duration || ''
        }
      });
    });

  } catch (error) {
    console.log("=== SERVER ERROR ===");
    console.log("Error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error",
      error: error.message
    });
  }
});

// ==================== UPDATE COURSE (Admin Only) - UPDATED WITHOUT PRICE & IMAGE ====================
server1.put("/api/courses/:id", (req, res) => {
  console.log("=== UPDATE COURSE ENDPOINT HIT ===");
  console.log("Course ID:", req.params.id);
  console.log("Request body:", req.body);
  
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
      console.log("Decoded token:", decoded);
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const courseId = req.params.id;
    const { title, description, instructor, duration } = req.body;

    // UPDATED QUERY - WITHOUT PRICE AND IMAGE_URL
    const query = `UPDATE courses 
                   SET title = ?, description = ?, instructor = ?, duration = ? 
                   WHERE id = ?`;
    
    console.log("Executing update query");
    console.log("With values:", [title, description, instructor || '', duration || '', courseId]);
    
    db.query(query, [title, description, instructor || '', duration || '', courseId], (error, result) => {
      if (error) {
        console.log("=== UPDATE ERROR ===");
        console.log("Error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to update course",
          error: error.message
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ 
          status: false, 
          message: "Course not found" 
        });
      }

      console.log("=== COURSE UPDATED SUCCESSFULLY ===");
      res.status(200).json({
        status: true,
        message: "Course updated successfully"
      });
    });

  } catch (error) {
    console.log("=== SERVER ERROR ===");
    console.log("Error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error",
      error: error.message
    });
  }
});

// ==================== DELETE COURSE (Admin Only) ====================
server1.delete("/api/courses/:id", (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const courseId = req.params.id;
    const query = `DELETE FROM courses WHERE id = ?`;
    
    db.query(query, [courseId], (error, result) => {
      if (error) {
        console.log("Delete error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to delete course" 
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ 
          status: false, 
          message: "Course not found" 
        });
      }

      res.status(200).json({
        status: true,
        message: "Course deleted successfully"
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== GET USER COUNT ====================
server1.get("/api/users/count", (req, res) => {
  const query = `SELECT COUNT(*) as count FROM users`;
  
  db.query(query, (error, results) => {
    if (error) {
      console.log("Database error:", error);
      return res.status(500).json({ 
        status: false, 
        message: "Failed to fetch user count" 
      });
    }

    res.status(200).json({
      status: true,
      count: results[0].count
    });
  });
});

// ==================== GET ALL TUTORS (Public - No Auth) ====================
server1.get("/api/tutors", (req, res) => {
  const query = `SELECT * FROM tutors ORDER BY created_at DESC`;
  
  db.query(query, (error, results) => {
    if (error) {
      console.log("Database error:", error);
      return res.status(500).json({ 
        status: false, 
        message: "Failed to fetch tutors" 
      });
    }

    res.status(200).json({
      status: true,
      data: results
    });
  });
});

// ==================== GET SINGLE TUTOR ====================
server1.get("/api/tutors/:id", (req, res) => {
  const tutorId = req.params.id;
  const query = `SELECT * FROM tutors WHERE id = ?`;
  
  db.query(query, [tutorId], (error, results) => {
    if (error) {
      return res.status(500).json({ 
        status: false, 
        message: "Database error" 
      });
    }

    if (results.length === 0) {
      return res.status(404).json({ 
        status: false, 
        message: "Tutor not found" 
      });
    }

    res.status(200).json({
      status: true,
      data: results[0]
    });
  });
});

// ==================== ADD TUTOR (Admin Only) ====================
server1.post("/api/tutors", (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    // Check if user is admin
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const { name, expertise, image, description } = req.body;

    if (!name || !expertise) {
      return res.status(400).json({ 
        status: false, 
        message: "Name and expertise are required" 
      });
    }

    const query = `INSERT INTO tutors (name, expertise, image, description) 
                   VALUES (?, ?, ?, ?)`;
    
    db.query(query, [name, expertise, image, description], (error, result) => {
      if (error) {
        console.log("Insert error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to add tutor" 
        });
      }

      res.status(201).json({
        status: true,
        message: "Tutor added successfully",
        data: {
          id: result.insertId,
          name,
          expertise,
          image,
          description
        }
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== UPDATE TUTOR (Admin Only) ====================
server1.put("/api/tutors/:id", (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const tutorId = req.params.id;
    const { name, expertise, image, description } = req.body;

    const query = `UPDATE tutors 
                   SET name = ?, expertise = ?, image = ?, description = ? 
                   WHERE id = ?`;
    
    db.query(query, [name, expertise, image, description, tutorId], (error, result) => {
      if (error) {
        console.log("Update error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to update tutor" 
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ 
          status: false, 
          message: "Tutor not found" 
        });
      }

      res.status(200).json({
        status: true,
        message: "Tutor updated successfully"
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== DELETE TUTOR (Admin Only) ====================
server1.delete("/api/tutors/:id", (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      console.log("JWT verification error:", jwtError);
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    const tutorId = req.params.id;
    const query = `DELETE FROM tutors WHERE id = ?`;
    
    db.query(query, [tutorId], (error, result) => {
      if (error) {
        console.log("Delete error:", error);
        return res.status(500).json({ 
          status: false, 
          message: "Failed to delete tutor" 
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ 
          status: false, 
          message: "Tutor not found" 
        });
      }

      res.status(200).json({
        status: true,
        message: "Tutor deleted successfully"
      });
    });

  } catch (error) {
    console.log("Server error:", error);
    res.status(500).json({ 
      status: false, 
      message: "Server error" 
    });
  }
});

// ==================== GET ALL USERS (Admin Only) ====================
server1.get("/api/users", (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: false, 
        message: "Unauthorized - No token provided" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, 'supersecretkey');
    } catch (jwtError) {
      return res.status(401).json({ 
        status: false, 
        message: "Invalid or expired token" 
      });
    }
    
    // Check if user is admin
    if (!decoded.role || decoded.role !== 'admin') {
      return res.status(403).json({ 
        status: false, 
        message: "Access denied. Admin only." 
      });
    }

    // Modified query to exclude admin users
    const query = `SELECT id, name, email, role, created_at 
                   FROM users 
                   WHERE role != 'admin' 
                   ORDER BY created_at DESC`;
    
    db.query(query, (error, results) => {
      if (error) {
        return res.status(500).json({ 
          status: false, 
          message: "Failed to fetch users",
          error: error.message
        });
      }

      res.status(200).json({
        status: true,
        data: results
      });
    });

  } catch (error) {
    res.status(500).json({ 
      status: false, 
      message: "Server error",
      error: error.message
    });
  }
});

