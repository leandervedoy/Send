require('dotenv').config(); // Load .env variables
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const express = require('express');
const sql = require('mssql');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const app = express();


// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.json());


// Serve static files
app.use(express.static(path.join(__dirname, 'dist')));

// MSSQL connection config
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET;

// ======================= AUTH ===========================

// Register
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).send('Username and password are required');

  try {
    const pool = await sql.connect(dbConfig);
    const userCheck = await pool.request()
      .input('username', sql.NVarChar(50), username)
      .query('SELECT * FROM Sent_Users WHERE Username = @username');

    if (userCheck.recordset.length > 0) {
      return res.status(400).send('Username already exists');
    }

     const emailCheck = await pool.request()
      .input('email', sql.NVarChar(50), email)
      .query('SELECT * FROM Sent_Users WHERE Email = @email');

    if (emailCheck.recordset.length > 0) {
      return res.status(400).send('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.request()
      .input('Username', sql.NVarChar(50), username)
      .input('PasswordHash', sql.NVarChar(255), hashedPassword)
      .input('Email', sql.NVarChar(255), email)
      .query(`
        INSERT INTO Sent_Users (Username, Email, PasswordHash, CreatedAt)
        OUTPUT INSERTED.UserID, INSERTED.Username
        VALUES (@Username, @Email, @PasswordHash, SYSDATETIME())
      `);


    const user = result.recordset[0];
    const token = jwt.sign({ id: user.UserID, username: user.Username }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, { httpOnly: true, maxAge: 3600 * 1000 });
    res.json({ message: 'Registration successful', token, user });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).send('DB error');
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password, rememberMe } = req.body;

  if (!username || !password) return res.status(400).send('Username and password are required');

  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .input('username', sql.NVarChar(50), username)
      .query('SELECT * FROM Sent_Users WHERE Username = @username');

    const user = result.recordset[0];
    if (!user) return res.status(400).send('Invalid username or password');

    const match = await bcrypt.compare(password, user.PasswordHash);
    if (!match) return res.status(400).send('Invalid username or password');
    
    const userID = user.UserID;
    const token = jwt.sign({ id: user.UserID, username: user.Username }, JWT_SECRET, { expiresIn: '1h' });

    const cookieOptions = { httpOnly: true, maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 3600 * 1000 };
    res.cookie('token', token, cookieOptions);
  
    res.json({ message: 'Login successful', token, userID });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('DB error');
  }
});


// ================== AUTH MIDDLEWARE ===================

// Middleware to check if the user is authenticated
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send('Access Denied');
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Token');
    }
    req.user = user;
    next();
  });
}


// =================== ROUTES ===========================

app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile!', user: req.user });
});

app.get('/messages', async (req, res) => {
  const conversationID = req.query.conversationID;

  if (!conversationID) {
    return res.status(400).send('Missing conversationID parameter');
  }

  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .input('conversationID', sql.Int, conversationID)
      .query(`
        SELECT TOP 50 m.MessageID, u.UserID AS SenderID, u.Username AS Sender, m.Content, m.CreatedAt
        FROM Sent_Messages m
        JOIN Sent_Users u ON m.SenderID = u.UserID
        WHERE m.ConversationID = @conversationID
        ORDER BY m.CreatedAt ASC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).send('DB error');
  }
});


app.post('/messages', async (req, res) => {
  const { senderID, content, conversationID } = req.body;
  if (!senderID || !content || !conversationID) {
    return res.status(400).send('Missing senderID, content or conversationID');
  }

  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .input('SenderID', sql.Int, senderID)
      .input('ConversationID', sql.Int, conversationID)
      .input('Content', sql.NVarChar(sql.MAX), content)
      .query(`
        INSERT INTO Sent_Messages (SenderID, ConversationID, Content, CreatedAt)
        OUTPUT INSERTED.MessageID, INSERTED.SenderID, INSERTED.Content, INSERTED.CreatedAt
        VALUES (@SenderID, @ConversationID, @Content, SYSDATETIME())
      `);
    res.json(result.recordset[0]);
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).send('DB error');
  }
});

app.get('/api/customers', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query('SELECT * FROM customers');
    res.json(result.recordset);
  } catch (err) {
    console.error('Error querying database: ' + err.stack);
    res.status(500).send('Error fetching data');
  }
});

app.get('/api/SentUsers', async (req, res) => {
  const excludeUserID = req.query.exclude;

  if (!excludeUserID) {
    return res.status(400).send('Missing exclude userID');
  }

  try {
    const pool = await sql.connect(dbConfig);

    // Query: select users excluding self and anyone in MyContacts
    const result = await pool.request()
      .input('excludeUserID', sql.Int, excludeUserID)
      .query(`
        SELECT su.*
        FROM Sent_Users su
        WHERE su.UserID != @excludeUserID
          AND su.UserID NOT IN (
            SELECT ContactUserID
            FROM Sent_Contacts
            WHERE UserID = @excludeUserID
          )
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error querying database: ' + err.stack);
    res.status(500).send('Error fetching data');
  }
});


app.get('/api/MyContacts', async (req, res) => {
  const userID = req.query.userID;

  if (!userID) {
    return res.status(400).send('Missing userID');
  }

  try {
    const pool = await sql.connect(dbConfig);

    const result = await pool.request()
      .input('userID', sql.Int, userID)
      .query(`
        SELECT su.UserID, su.Username, su.Email
        FROM Sent_Contacts c
        JOIN Sent_Users su ON c.ContactUserID = su.UserID
        WHERE c.UserID = @userID
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching contacts:', err);
    res.status(500).send('Error fetching contacts');
  }
});

// POST /api/MyContacts
app.post('/api/MyContacts', async (req, res) => {
  const { userID, contactID } = req.body;

  if (!userID || !contactID) {
    return res.status(400).send('Missing userID or contactID');
  }

  try {
    const pool = await sql.connect(dbConfig);

    // Optional: check if contact already exists
    const check = await pool.request()
      .input('userID', sql.Int, userID)
      .input('contactID', sql.Int, contactID)
      .query(`
        SELECT * FROM Sent_Contacts
        WHERE UserID = @userID AND ContactUserID = @contactID
      `);

    if (check.recordset.length > 0) {
      return res.status(409).send('Contact already exists');
    }

    // Insert new contact
    await pool.request()
      .input('userID', sql.Int, userID)
      .input('contactID', sql.Int, contactID)
      .query(`
        INSERT INTO Sent_Contacts (UserID, ContactUserID)
        VALUES (@userID, @contactID)
      `);

    res.status(200).send('Contact added');

  } catch (err) {
    console.error('Failed to add contact:', err);
    res.status(500).send('Failed to add contact');
  }
});

// REMOVE CONTACT
app.delete('/api/MyContacts', async (req, res) => {
  const { userID, contactID } = req.body;

  if (!userID || !contactID) {
    return res.status(400).send('Missing userID or contactID');
  }

  try {
    const pool = await sql.connect(dbConfig);

    await pool.request()
      .input('userID', sql.Int, userID)
      .input('contactID', sql.Int, contactID)
      .query(`
        DELETE FROM Sent_Contacts
        WHERE UserID = @userID AND ContactUserID = @contactID
      `);

    res.status(200).send('Contact removed');
  } catch (err) {
    console.error('Error deleting contact:', err);
    res.status(500).send('Failed to remove contact');
  }
});




app.post('/api/checkOrCreateConversation', async (req, res, next) => {
  const { userA, userB } = req.body;

  try {
    const pool = await sql.connect(dbConfig);

    // 1. Check if a conversation already exists with exactly these 2 users
    const checkQuery = `
      SELECT cm.ConversationID
      FROM Sent_ConversationMembers cm
      JOIN Sent_Conversations c ON c.ConversationID = cm.ConversationID
      WHERE c.IsGroup = 0
        AND cm.ConversationID IN (
            SELECT ConversationID
            FROM Sent_ConversationMembers
            WHERE UserID IN (@userA, @userB)
            GROUP BY ConversationID
            HAVING COUNT(DISTINCT UserID) = 2
        )
      GROUP BY cm.ConversationID
      HAVING COUNT(*) = 2
    `;

    const checkResult = await pool.request()
      .input('userA', sql.Int, userA)
      .input('userB', sql.Int, userB)
      .query(checkQuery);

    let conversationID;

    if (checkResult.recordset.length > 0) {
      conversationID = checkResult.recordset[0].ConversationID;
    } else {
      // 2. Create a new conversation
      const insertConversation = await pool.request()
        .input('createdBy', sql.Int, userA)
        .query(`
          INSERT INTO Sent_Conversations (Name, IsGroup, CreatedBy, CreatedAt)
          OUTPUT INSERTED.ConversationID
          VALUES (NULL, 0, @createdBy, GETDATE())
        `);

      conversationID = insertConversation.recordset[0].ConversationID;

      // 3. Add both users to Sent_ConversationMembers
      await pool.request()
        .input('conversationID', sql.Int, conversationID)
        .input('userA', sql.Int, userA)
        .input('userB', sql.Int, userB)
        .query(`
          INSERT INTO Sent_ConversationMembers (ConversationID, UserID, JoinedAt)
          VALUES
            (@conversationID, @userA, GETDATE()),
            (@conversationID, @userB, GETDATE())
        `);
    }

    res.json({ conversationID });
  } catch (err) {
    console.error('Error during conversation check/create:', err);
    res.status(500).send('Server error');
  }
});


// =================== SERVER ===========================

// Start server and check DB connection
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  try {
    await sql.connect(dbConfig);
    console.log('✅ Connected to SQL Server successfully.');
  } catch (err) {
    console.error('❌ Failed to connect to SQL Server:', err.message);
  }
});
