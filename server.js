import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import pkg from 'pg';
const { Pool } = pkg;
import session from 'express-session';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// Initialize Supabase client for server-side operations
const supabaseUrl = 'https://ooyzqrrdvaebqyectlgw.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9veXpxcnJkdmFlYnF5ZWN0bGd3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MTgwMTgwMiwiZXhwIjoyMDY3Mzc3ODAyfQ.bU_JbE-DtCD0o2pdE7LXg5anjGU0qEbp-liS0bnWxhw';
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const app = express();
const PORT = process.env.PORT || 4001;
const JWT_SECRET = process.env.JWT_SECRET || "ADIIKING3344aa";
const SECRET_KEY = process.env.SECRET_KEY || "SONY123";


// Better CORS configuration
app.use(cors({
  origin: ['http://localhost:4001', 'http://localhost:3000', 'https://civic-port.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Set up session middleware
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// Set up __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

//////////////////////////////////////////////////////////////////////////////////////////////////////////

// Set up Supabase PostgreSQL database connection
const db = new Pool({
  host: process.env.SUPABASE_HOST,
  port: process.env.SUPABASE_PORT || 5432,
  database: process.env.SUPABASE_DATABASE,
  user: process.env.SUPABASE_USER,
  password: process.env.SUPABASE_PASSWORD,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
db.connect()
  .then(() => {
    console.log('Connected to Supabase PostgreSQL database');
  })
  .catch((error) => {
    console.error('Database Connection Failed:', error);
  });


/////////////////////////////////////////////////////////////////////////////////////////////////////////////



// Note: Signin/Signup routes removed - now handled by Supabase Auth

// Supabase authentication middleware
const authenticateSupabaseToken = async (req, res, next) => {
  console.log('Auth middleware called for:', req.path);
  const token = req.headers['authorization']?.replace('Bearer ', '');

  console.log('Token received:', token ? 'Yes' : 'No');

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);

    console.log('Supabase auth result:', { user: user?.email, error: error?.message });

    if (error || !user) {
      console.log('Invalid token or user not found');
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    console.log('Authentication successful for user:', user.email);
    next();
  } catch (error) {
    console.log('Token verification failed:', error.message);
    return res.status(401).json({ error: 'Token verification failed' });
  }
};

// Keep old middleware for backward compatibility during migration
const authenticateToken = authenticateSupabaseToken;

app.get('/', (req, res) => {
  res.send('Welcome to the API'); // You can customize this response
});
// Route to get protected data
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected data' });
});

// Route to get user data by email
app.get('/user/:email', authenticateToken, async (req, res) => {
  const email = req.params.email;

  // Query the database to get user data
  const query = 'SELECT * FROM usersdb WHERE email = $1';

  try {
    const result = await db.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove sensitive information like password before sending
    const user = {...result.rows[0]};
    delete user.password;

    res.json(user);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});




//Route To get Tehsils From Database To Show On Signup page
app.get('/api/gettehsils', async (req, res) => {
  const query = 'SELECT tehsil FROM tehsils';

  try {
    const result = await db.query(query);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error Fetching Tehsils', err);
    res.status(500).json({error: 'Error Fetching Tehsils'});
  }
});


// Note: Custom signup route removed - now handled by Supabase Auth


////////////////////////////////////////////////////////////////////////////////////////////////////////////////



// Admin signup route
app.post('/adminsignup', async (req, res) => {
  const { First_Name, Last_Name, Email, Password, Tehsil, Secret_Key } = req.body;

  // Check if the secret key matches
  if (Secret_Key !== SECRET_KEY) {
    return res.status(401).send('Invalid Secret Key');
  }

  try {
    console.log('Admin signup attempt:', { First_Name, Last_Name, Email, Tehsil });

    // Step 1: Create user in Supabase Auth first (required for foreign key)
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: Email,
      password: Password,
      email_confirm: true,
      user_metadata: {
        role: 'admin' // Mark as admin to prevent regular user profile creation
      }
    });

    if (authError) {
      console.error('Supabase auth error:', authError);
      if (authError.code === 'email_exists') {
        return res.status(400).json({ message: 'Email already exists' });
      }
      return res.status(500).json({
        message: 'Failed to create admin account',
        error: authError.message
      });
    }

    console.log('Admin user created in Supabase Auth:', authData.user.id);

    // Step 2: Create admin profile in adminsdb
    const insertQuery = 'INSERT INTO adminsdb (id, first_name, last_name, tehsil) VALUES ($1, $2, $3, $4) RETURNING id';
    const result = await db.query(insertQuery, [authData.user.id, First_Name, Last_Name, Tehsil]);

    console.log('Admin profile created successfully:', result.rows[0]);
    return res.status(201).json({
      message: 'Admin registration successful',
      admin_id: result.rows[0].id
    });

  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ message: 'Registration failed' });
  }
});




//Admin Signin (Updated for Supabase Auth)
app.post('/adminsignin', async (req, res) => {
  const { Email, Password } = req.body;

  try {
    console.log('Admin signin attempt:', Email);

    // Sign in with Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: Email,
      password: Password
    });

    if (authError) {
      console.error('Supabase admin signin error:', authError);
      return res.status(401).json({ message: 'Incorrect Email Or Password' });
    }

    // Check if user is an admin by looking up in adminsdb
    const adminQuery = 'SELECT * FROM adminsdb WHERE id = $1';
    const adminResult = await db.query(adminQuery, [authData.user.id]);

    if (adminResult.rows.length === 0) {
      console.log('User is not an admin:', authData.user.email);
      return res.status(401).json({ message: 'Access denied. Admin privileges required.' });
    }

    const admin = adminResult.rows[0];
    console.log('Admin signin successful:', admin.id);

    // Create JWT token for backward compatibility
    const Token = jwt.sign({
      id: admin.id,
      email: authData.user.email,
      Tehsil: admin.tehsil,
      role: 'admin'
    }, JWT_SECRET, { expiresIn: '1h' });

    // Send a success response
    res.json({
      success: true,
      Token,
      email: authData.user.email,
      id: admin.id,
      Tehsil: admin.tehsil,
      supabase_session: authData.session
    });

  } catch (err) {
    console.error('Admin signin error:', err);
    res.status(500).json({ message: 'Internal server Error' });
  }
});

//Authenticating Admin Token
const authenticateadminToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extracts the token from 'Authorization' header
  if (!token) { // Check if the token is missing
    return res.status(401).json({ message: 'No token provided' }); // Respond with 401 if no token is found
  }
  // Verify the token
  jwt.verify(token, JWT_SECRET, (err, admin) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' }); // Respond with 403 if the token is invalid
    }
    // Check if the admin object has the 'Tehsil' property
    if (!admin.Tehsil) {
      return res.status(403).json({ message: 'Tehsil information missing from token' });
    }
    req.admin = admin; // Attach the decoded admin data to the request object
    next(); // Proceed to the next middleware or route handler
  });
};


app.get('/', (req, res) => {
  res.send('Welcome to the API'); // You can customize this response
});
// Route to get protected data
app.get('/protectedadmin', authenticateadminToken, (req, res) => {
  res.json({ message: 'This is protected data' });
});

// Route to get admin data by email
app.get('/admin/:email', authenticateadminToken, async (req, res) => {
  const email = req.params.email;

  // Query the database to get admin data
  const query = 'SELECT * FROM adminsdb WHERE email = $1';

  try {
    const result = await db.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Remove sensitive information like password before sending
    const admin = {...result.rows[0]};
    delete admin.password;

    res.json(admin);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////





// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, path.join(__dirname, 'uploads/'));
//   },
//   filename: (req, file, cb) => {
//     cb(null, Date.now() + path.extname(file.originalname));
//   },
// });
// const upload = multer({ storage });
//const upload = multer({ storage: multer.memoryStorage() });

//app.use(express.static('uploads')); // Serve static files from the 'uploads' directory

// Configure multer to store files in 'uploads/' directory
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'uploads/'); // Save files to 'uploads' directory
//   },
//   filename: (req, file, cb) => {
//     cb(null, `${Date.now()}-${file.originalname}`); // Unique filename
//   },
// });

// const upload = multer({ storage: storage });

// // Route to handle form submissions
// app.post(
//   '/newrequest',
//   upload.fields([
//     { name: 'image', maxCount: 1 },
//     { name: 'document', maxCount: 1 },
//   ]),
//   (req, res) => {
//     const { issue, location, description, name, status, userId, schedule, tehsil } = req.body; // Extract body parameters

//     // Get file paths
//     const imagePath = req.files['image']
//       ? `uploads/${req.files['image'][0].filename}`
//       : null;
//     const documentPath = req.files['document']
//       ? `uploads/${req.files['document'][0].filename}`
//       : null;

//     // Validate required fields
//     if (
//       !issue ||
//       !location ||
//       !description ||
//       !name ||
//       !userId ||
//       !schedule ||
//       !tehsil ||
//       !imagePath
//     ) {
//       return res
//         .status(400)
//         .json({ message: 'All required fields must be filled.' }); // Bad request if validation fails
//     }

//     // SQL query to insert the new request into the database
//     const query =
//       'INSERT INTO requests (issue, location, description, image, document, name, status, userId, schedule, tehsil) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

//     // Execute the database query
//     db.query(
//       query,
//       [
//         issue,
//         location,
//         description,
//         imagePath,
//         documentPath || null,
//         name,
//         status,
//         userId,
//         schedule,
//         tehsil,
//       ],
//       (err, result) => {
//         if (err) {
//           console.error(err); // Log any errors to the console
//           return res.status(500).json({ message: 'Internal Server Error' }); // Internal server error response
//         }
//         res.status(201).json({ message: 'Request submitted successfully!' }); // Successful response
//       }
//     );
//   }
// );



// // Ensure 'uploads/' directory exists
// if (!fs.existsSync('uploads')) {
//   fs.mkdirSync('uploads', { recursive: true });
//   console.log('Created uploads/ directory.');
// }

// Multer configuration for file storage




// // Configure multer for file storage
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'uploads/');
//   },
//   filename: (req, file, cb) => {
//     cb(null, Date.now() + path.extname(file.originalname));
//   },
// });
// const upload = multer({ storage: storage });




////////////////////////////////////////////////////////////////////////////////////////////////////





// //// Route to handle new request submissions
// app.post('/newrequest', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'document', maxCount: 1 }]), (req, res) => {
//   const { issue, location, description, name, status, userId, schedule, tehsil } = req.body; // Extract body parameters

//   // Get image path and document
//   const imagePath = req.files['image'] && req.files['image'][0] ? `uploads/${req.files['image'][0].filename}` : null;
//   const document = req.files['document'] && req.files['document'][0] ? `uploads/${req.files['document'][0].filename}` : null;

//   // Validate required fields
//   if (!issue || !location || !description || !imagePath || !name || !userId || !schedule || !tehsil) {
//     return res.status(400).json({ message: 'All required fields must be filled.' }); // Bad request if validation fails
//   }

//   // SQL query to insert the new request into the database
//   const query = 'INSERT INTO requests (issue, location, description, image, document, name, status, userId, schedule, tehsil) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

//   // Execute your database query here
//   db.query(query, [issue, location, description, imagePath, document || null, name, status, userId, schedule, tehsil], (err, result) => {
//     if (err) {
//       console.error(err); // Log any errors to the console
//       return res.status(500).json({ message: 'Internal Server Error' }); // Internal server error response
//     }
//     res.status(201).json({ message: 'Request submitted successfully!' }); // Successful response
//   });
// });



/////////////////////////////////////////////////////////////////////////////////////////////////


// Configure Multer to save files correctly in the 'uploads' directory
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Save to 'uploads' directory
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`; // Ensure unique filenames
    cb(null, uniqueName);
  },
});

// Only allow image and document files
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true); // Accept file
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'), false);
  }
};

// Configure upload handler with limits and file filtering
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max file size
  fileFilter: fileFilter,
});

// Route to handle new request submissions
app.post(
  '/newrequest',
  upload.fields([{ name: 'image', maxCount: 1 }, { name: 'document', maxCount: 1 }]),
  async (req, res) => {
    console.log('=== NEW REQUEST ROUTE HIT ===');
    console.log('Request method:', req.method);
    console.log('Request path:', req.path);
    console.log('Content-Type:', req.headers['content-type']);

    const { issue, location, description, name, status, userId, schedule, tehsil } = req.body;

    // Handle schedule field - convert "null" string to actual null
    const scheduleValue = (schedule === 'null' || schedule === null || schedule === undefined || schedule === '') ? null : schedule;

    console.log('Received request data:', {
      issue, location, description, name, status, userId, schedule: scheduleValue, tehsil
    });
    console.log('Received files:', req.files);

    // Get image and document paths
    const imagePath = req.files['image'] ? `uploads/${req.files['image'][0].filename}` : null;
    const documentPath = req.files['document'] ? `uploads/${req.files['document'][0].filename}` : null;

    console.log('File paths:', { imagePath, documentPath });

    // Validate required fields (schedule is optional)
    if (!issue || !location || !description || !imagePath || !name || !userId || !tehsil) {
      const missingFields = [];
      if (!issue) missingFields.push('issue');
      if (!location) missingFields.push('location');
      if (!description) missingFields.push('description');
      if (!imagePath) missingFields.push('image');
      if (!name) missingFields.push('name');
      if (!userId) missingFields.push('userId');
      if (!tehsil) missingFields.push('tehsil');

      console.log('Missing required fields:', missingFields);
      return res.status(400).json({
        message: 'Missing required fields: ' + missingFields.join(', ')
      });
    }

    // SQL query to insert the new request into the database
    const query = `
      INSERT INTO requests (issue, location, description, image, document, name, status, user_id, schedule, tehsil)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id
    `;

    try {
      // Execute the database query
      const result = await db.query(
        query,
        [issue, location, description, imagePath, documentPath, name, status, userId, scheduleValue, tehsil]
      );

      console.log('Request submitted successfully:', result.rows[0]);
      res.status(201).json({ message: 'Request submitted successfully!' });
    } catch (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
  }
);





////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route to get all requests from database and to show on UI
//For user Panel
app.get('/requests', authenticateToken, async (req, res) => {
  const sql = 'SELECT * FROM requests ORDER BY created_at DESC';

  try {
    const results = await db.query(sql);
    res.json(results.rows);
  } catch (err) {
    console.error('Error fetching requests:', err);
    res.status(500).send('Error fetching requests');
  }
});


//////////////////////////////////////////////////////////////////////////////////
//Route To Get The Dropped Complaints From Database To Show On UserDashboard

app.get('/api/requests/dropped', authenticateToken, async (req, res) => {
  const query = "SELECT * FROM requests WHERE status = 'Dropped'";

  try {
    const result = await db.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching dropped requests:', err);
    res.status(500).send('Error Fetching Requests');
  }
});




//Route To Update The Request Open Or Close status and Schedule date Edited by Admin

app.put('/reports/:id', async (req, res) => {
  const { id } = req.params;
  const { status, schedule } = req.body;

  console.log('Updating report:', { id, status, schedule });

  try {
    // Normalize status to match database constraint
    const normalizedStatus = status ? status.charAt(0).toUpperCase() + status.slice(1).toLowerCase() : status;

    // Handle schedule - convert empty string or "null" to null
    const scheduleValue = (schedule === '' || schedule === 'null' || schedule === null) ? null : schedule;

    console.log('Normalized values:', { normalizedStatus, scheduleValue });

    // Update the report in the database
    const result = await db.query(
      'UPDATE requests SET status = $1, schedule = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [normalizedStatus, scheduleValue, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Report not found' });
    }

    console.log('Report updated successfully:', result.rows[0]);
    res.status(200).json({
      message: 'Report updated successfully',
      report: result.rows[0]
    });
  } catch (err) {
    console.error('Error updating report:', err);
    res.status(500).json({
      message: 'Error updating the report',
      error: err.message
    });
  }
});


// Route to get all requests from database and show on UI (For Admin Panel)
app.get('/adminrequests', authenticateadminToken, async (req, res) => {
  const admintehsil = req.admin.Tehsil; // Assuming this gets the Tehsil from the admin token
  try {
    const requests = await db.query('SELECT * FROM requests WHERE tehsil = $1', [admintehsil]);
    res.json(requests.rows);
  } catch (error) {
    console.error(`Error fetching requests for ${admintehsil}:`, error);
    res.status(500).json({ message: 'Error fetching requests' });
  }
});

//Route to get document request From the database
// Serve PDF document as BLOB from database
app.get('/download-pdf/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT document FROM requests WHERE id = $1';

  try {
    const results = await db.query(sql, [id]);

    if (results.rows.length === 0) {
      return res.status(404).send('No PDF found');
    }

    const pdfData = results.rows[0].document;

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `inline; filename="document-${id}.pdf"`,
    });

    res.send(pdfData); // Send the PDF as binary data
  } catch (err) {
    console.error('Error fetching document:', err);
    return res.status(400).send('Error fetching Document');
  }
});





// Route to get the user Contact_Number from database to show on Admin Panel
app.get('/request-contact/:userId', authenticateadminToken, async (req, res) => {
  const userId = req.params.userId;
  const sql = 'SELECT contact_number FROM usersdb WHERE id = $1';

  try {
    const results = await db.query(sql, [userId]);

    if (results.rows.length > 0) {
      res.json({ contactNumber: results.rows[0].contact_number });
    } else {
      res.status(404).send('Contact not found');
    }
  } catch (err) {
    console.error('Error fetching contact number:', err);
    res.status(500).send('Error fetching contact number');
  }
});



//Route To get The Requests Reported By a Specific USer To Show On UserDashboard

app.get('/user-requests/:userId', async (req, res) => {
  const userId = req.params.userId;

  const sql = 'SELECT * FROM requests WHERE user_id = $1 ORDER BY created_at DESC';

  try {
    const results = await db.query(sql, [userId]);
    res.status(200).json(results.rows);
  } catch (err) {
    console.error('Error fetching user requests:', err);
    return res.status(500).send('Failed to fetch user requests');
  }
});


///////////////////////////////////////////////////////////////////////////////////////////////
//Route From MyAdmin To Add New Tehsil
app.post('/api/addTehsil', async (req, res) => {
  const { newtehsil } = req.body;

  const query = 'INSERT INTO tehsils (tehsil) VALUES ($1) RETURNING id';

  try {
    const result = await db.query(query, [newtehsil]);
    console.log('Tehsil added successfully:', result.rows[0]);
    res.status(200).json({ message: 'Tehsil Added Successfully' });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQL unique violation error code
      res.status(400).json({ error: 'Tehsil already exists' });
    } else {
      console.error('Error Adding The Tehsil', err);
      res.status(500).json({ error: 'Failed To Add Tehsil' });
    }
  }
});

/////////////////////////////////////////////////////////////////////////////////////////////
//Route To Send Invite

app.post('/api/sendInvite', async (req, res) => {
  const { userEmail, neighborEmail } = req.body;

  // Email configuration using environment variables
  const transporter = nodemailer.createTransport({
    service: 'gmail', // e.g., Gmail, Yahoo, Outlook
    auth: {
      user: process.env.EMAIL_USER || 'elionjohn3@gmail.com', // Your email address
      pass: process.env.EMAIL_PASS || 'ADIIKING34aa@', // Your email password or app-specific password
    },
  });

  const mailOptions = {
    from: userEmail, // Sender's email address
    to: neighborEmail, // Receiver's email address
    subject: 'Invitation to Join Our Neighborhood Network',
    text: `Hi there,
   We Invite You To Join Our ClickAndFix Community For Better Enviroment And To Get Easy Access
   To Your Local Government For Reporting Any issue. 'Click Here' link below to get started!
  Best regards,
  ClickAndFix Team`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).send('Invitation sent successfully!');
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send('Failed to send invitation.');
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
