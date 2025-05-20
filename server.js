import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import mysql from 'mysql2';
import session from 'express-session';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import nodemailer from 'nodemailer';

const app = express();
const PORT = 4000;
const JWT_SECRET = "ADIIKING3344aa";
const SECRET_KEY = "SONY123";

// Better CORS configuration
app.use(cors({
  origin: 'http://localhost:3000', // Your frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
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


// Set up database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'ADIIKING34',
  database: 'civicportal',
});

db.connect((error) => {
  if (error) {
    console.error('Database Connection Failed:', error);
    return;
  }
  console.log('Connected to the database');
});


/////////////////////////////////////////////////////////////////////////////////////////////////////////////



// Signin route with JWT
app.post('/signin', (req, res) => {
  const { Email, Password } = req.body;
  const query = 'SELECT * FROM usersdb WHERE Email = ?';

  db.query(query, [Email], (err, result) => {
    if (err) {
      res.status(500).send('Internal server error');
      return;
    }
    if (result.length === 0) {
      return res.status(401).send('Incorrect email or password.');
    }

    const user = result[0];
    if (Password !== user.Password) {
      return res.status(401).send('Incorrect email or password.');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.Email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, email: user.Email , id: user.id });

  });
});

//  authenticating JWT tokens
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; //extracts 'authorization' from req.header array , if present then split by one spaec
  if (token == null) return res.sendStatus(401);              //if there is no token

  //if there is a token then verifying the token
  jwt.verify(token, JWT_SECRET, (err, user) => { //JWT secret to decode the token
    if (err) return res.sendStatus(403);
    req.user = user;                //the Decoded User information attached to the request as req.user
    next();                        //for next operation
  });
};

app.get('/', (req, res) => {
  res.send('Welcome to the API'); // You can customize this response
});
// Route to get protected data
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected data' });
});

// Route to get user data by email
app.get('/user/:email', authenticateToken, (req, res) => {
  const email = req.params.email;

  // Query the database to get user data
  const query = 'SELECT * FROM usersdb WHERE Email = ?';

  db.query(query, [email], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove sensitive information like password before sending
    const user = {...result[0]};
    delete user.Password;

    res.json(user);
  });
});




//Route To get Tehsils From Database To Show On Signup page
app.get('/api/gettehsils' , (req , res) => {
  const query = 'SELECT tehsil FROM Tehsils';
  db.query(query , (err, result) => {
    if(err){
      console.error('Error Fetching Tehsils' , err)
      res.status(500).json({error:'Error Fetching Tehsils'})
    }else{
      res.status(200).json(result)
    }
  });
});


// Custom signup route
app.post('/signup', (req, res) => {
  const { First_Name, Last_Name, Email, Contact_Number, Password, Tehsil , Location } = req.body;


  db.query('SELECT Email FROM usersdb WHERE Email = ?', [Email], (err, result) => {
    if (err) {
      res.status(500).send('Internal server error');
      return;
    }
    if (result.length > 0) {
      return res.status(400).send('Email already exists');
    }

    const sql = 'INSERT INTO usersdb (First_Name, Last_Name, Email, Contact_Number, Password, Tehsil, Location) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [First_Name, Last_Name, Email, Contact_Number, Password, Tehsil , Location], (err, result) => {
      if (err) {
        res.status(500).send('Registration failed');
        return;
      }
      console.log('User registered successfully:', result);
      return res.status(200).json({ message: 'Signup successful' });
    });
  });
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////



// Admin signup route
app.post('/adminsignup', (req, res) => {
  const { First_Name, Last_Name, Email, Password, Tehsil , Secret_Key } = req.body;

  // Check if the secret key matches
  if (Secret_Key !== SECRET_KEY) {
    return res.status(401).send('Invalid Secret Key');
  }

  db.query('SELECT Email FROM adminsdb WHERE Email = ?', [Email], (err, result) => {
    if (err) {
      res.status(500).send('Internal server error');
      return;
    }
    if (result.length > 0) {
      return res.status(400).send('Email already exists');
    }

    const sql = 'INSERT INTO adminsdb (First_Name, Last_Name, Email, Password , Tehsil) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [First_Name, Last_Name, Email, Password , Tehsil], (err, result) => {
      if (err) {
        res.status(500).send('Registration failed');
        return;
      }
      console.log('Admin registered successfully:', result);
      return res.status(201).json({ message: 'Signup successful' });
    });
  });
});




//Admin Signin
app.post('/adminsignin' , (req , res) => {
  const {Email , Password} = req.body;
  const query = 'SELECT * FROM adminsdb WHERE Email = ?';

  db.query (query , [Email] , (err , result ) => {
      if(err) {
        res.status(500).send('Internal server Error')
        return
      }
      if(result.length === 0 ) {
        res.status(401).send('Incorrect Email Or Password');
        return
      }

      const admin = result[0];

      if(Password !== admin.Password){
        res.status(401).send('Incorrect Email Or Password')
        return
      }

      const Token = jwt.sign({ id: admin.Admin_id, email: admin.Email , Tehsil: admin.Tehsil}, JWT_SECRET ,{ expiresIn: '1h' });

     // Send a success response
     res.json({ success: true, Token, email: admin.Email , id : admin.Admin_id , Tehsil: admin.Tehsil});

  })

})

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
app.get('/admin/:email', authenticateadminToken, (req, res) => {
  const email = req.params.email;

  // Query the database to get admin data
  const query = 'SELECT * FROM adminsdb WHERE Email = ?';

  db.query(query, [email], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Remove sensitive information like password before sending
    const admin = {...result[0]};
    delete admin.Password;

    res.json(admin);
  });
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
  (req, res) => {
    const { issue, location, description, name, status, userId, schedule, tehsil } = req.body;

    // Get image and document paths
    const imagePath = req.files['image'] ? `uploads/${req.files['image'][0].filename}` : null;
    const documentPath = req.files['document'] ? `uploads/${req.files['document'][0].filename}` : null;

    // Validate required fields
    if (!issue || !location || !description || !imagePath || !name || !userId || !schedule || !tehsil) {
      return res.status(400).json({ message: 'All required fields must be filled.' });
    }

    // SQL query to insert the new request into the database
    const query = `
      INSERT INTO requests (issue, location, description, image, document, name, status, userId, schedule, tehsil)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute the database query
    db.query(
      query,
      [issue, location, description, imagePath, documentPath, name, status, userId, schedule, tehsil],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Internal Server Error' });
        }
        res.status(201).json({ message: 'Request submitted successfully!' });
      }
    );
  }
);





////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route to get all requests from database and to show on UI
//For user Panel
app.get('/requests', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM requests ORDER BY created_at DESC';
  db.query(sql, (err, results) => {
    if (err) {
      res.status(500).send('Error fetching requests');
      return;
    }
    res.json(results);
  });
});


//////////////////////////////////////////////////////////////////////////////////
//Route To Get The Dropped Complaints From Database To Show On UserDashboard

app.get('/api/requests/dropped' , authenticateToken , (req , res) => {
  const query = "SELECT * FROM requests WHERE status = 'Dropped'";
  db.query(query , (err , result) => {
    if (err) {
      res.status(500).send('Error Fetching Requests');
      return;
    }
    res.json(result);
  });
});




//Route To Update The Request Open Or Close status and Schedule date Edited by Admin

app.put('/reports/:id', (req, res) => {
  const { id } = req.params;
  const { status, schedule } = req.body;

  // Update the report in the database
  db.query(
    'UPDATE requests SET status = ?, schedule = ? WHERE id = ?',
    [status, schedule, id],
    (err, result) => {
      if (err) {
        res.status(500).send('Error updating the report');
      } else {
        res.status(200).send('Report updated successfully');
      }
    }
  );
});


// Route to get all requests from database and show on UI (For Admin Panel)
app.get('/adminrequests', authenticateadminToken, async (req, res) => {
  const admintehsil = req.admin.Tehsil; // Assuming this gets the Tehsil from the admin token
  try {
    const [requests] = await db.promise().query('SELECT * FROM requests WHERE tehsil = ?', [admintehsil]);
    res.json(requests);
  } catch (error) {
    console.error(`Error fetching requests for ${admintehsil}:`, error);
    res.status(500).json({ message: 'Error fetching requests' });
  }
});

//Route to get document request From the database
// Serve PDF document as BLOB from database
app.get('/download-pdf/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT document FROM requests WHERE id = ?';

  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.status(400).send('Error fetching Document');
    }

    if (results.length === 0) {
      return res.status(404).send('No PDF found');
    }

    const pdfData = results[0].document;

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `inline; filename="document-${id}.pdf"`,
    });

    res.send(pdfData); // Send the PDF as binary data
  });
});





// Route to get the user Contact_Number from database to show on Admin Panel
app.get('/request-contact/:userId', authenticateadminToken, (req, res) => {
  const userId = req.params.userId;
  const sql = 'SELECT Contact_Number FROM usersdb WHERE id = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching contact number:', err);
      res.status(500).send('Error fetching contact number');
      return;
    }
    if (results.length > 0) {
      res.json({ contactNumber: results[0].Contact_Number });
    } else {
      res.status(404).send('Contact not found');
    }
  });
});



//Route To get The Requests Reported By a Specific USer To Show On UserDashboard

app.get('/user-requests/:userId', (req, res) => {
  const userId = req.params.userId;

  const sql = 'SELECT * FROM requests WHERE userId = ? ORDER BY created_at DESC';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching user requests:', err);
      return res.status(500).send('Failed to fetch user requests');
    }

    res.status(200).json(results);
  });
});


///////////////////////////////////////////////////////////////////////////////////////////////
//Route From MyAdmin To Add New Tehsil
app.post('/api/addTehsil', (req, res) => {
  const { newtehsil } = req.body;

  const query = 'INSERT INTO tehsils (tehsil) VALUES (?)';
  db.query(query, [newtehsil], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        res.status(400).json({ error: 'Tehsil already exists' });
      } else {
        console.error('Error Adding The Tehsil', err);
        res.status(500).json({ error: 'Failed To Add Tehsil' });
      }
    } else {
      res.status(200).json({ message: 'Tehsil Added Successfully' });
    }
  });
});

/////////////////////////////////////////////////////////////////////////////////////////////
//Route To Send Invite

app.post('/api/sendInvite', async (req, res) => {
  const { userEmail, neighborEmail } = req.body;

  // Replace with your email credentials
  const transporter = nodemailer.createTransport({
    service: 'gmail', // e.g., Gmail, Yahoo, Outlook
    auth: {
      user: 'elionjohn3@gmail.com', // Your email address
      pass: 'ADIIKING34aa@', // Your email password or app-specific password
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
