const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '2468',
  database: 'railway_management'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to database');
});

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, 'secret_key', (err, user) => {
      if (err) {
        console.error('JWT verification failed', err);
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};



app.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Password hashing failed', err);
      return res.status(500).json({ error: err.message });
    }
    db.query('INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, role], (err, results) => {
      if (err) {
        console.error('User registration failed', err);
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: 'User registered' });
    });
  });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM Users WHERE username = ?', [username], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
      const user = results[0];
      bcrypt.compare(password, user.password_hash, (err, match) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!match) return res.status(401).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, role: user.role }, 'secret_key');
        res.json({ token, role: user.role });
      });
    });
  });
  

app.post('/trains', authenticateJWT, (req, res) => {
  if (req.user.role !== 'Admin') return res.sendStatus(403);
  const { train_name, source, destination, total_seats } = req.body;
  db.query('INSERT INTO Trains (train_name, source, destination, total_seats) VALUES (?, ?, ?, ?)', [train_name, source, destination, total_seats], (err, results) => {
    if (err) {
      console.error('Adding train failed', err);
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'Train added' });
  });
});

app.get('/seats', (req, res) => {
  const { source, destination } = req.query;
  db.query('SELECT * FROM Trains WHERE source = ? AND destination = ?', [source, destination], (err, results) => {
    if (err) {
      console.error('Fetching seat availability failed', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

app.post('/book', authenticateJWT, (req, res) => {
  const { train_id, seat_count } = req.body;
  db.query('SELECT total_seats FROM Trains WHERE id = ?', [train_id], (err, results) => {
    if (err) {
      console.error('Fetching train details failed', err);
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) return res.status(404).json({ message: 'Train not found' });
    const train = results[0];
    if (train.total_seats < seat_count) return res.status(400).json({ message: 'Not enough seats' });
    db.query('START TRANSACTION', (err) => {
      if (err) {
        console.error('Starting transaction failed', err);
        return res.status(500).json({ error: err.message });
      }
      db.query('UPDATE Trains SET total_seats = total_seats - ? WHERE id = ?', [seat_count, train_id], (err, results) => {
        if (err) {
          console.error('Updating seats failed', err);
          db.query('ROLLBACK', () => {});
          return res.status(500).json({ error: err.message });
        }
        db.query('INSERT INTO Bookings (user_id, train_id, seat_count) VALUES (?, ?, ?)', [req.user.id, train_id, seat_count], (err, results) => {
          if (err) {
            console.error('Inserting booking failed', err);
            db.query('ROLLBACK', () => {});
            return res.status(500).json({ error: err.message });
          }
          db.query('COMMIT', (err) => {
            if (err) {
              console.error('Committing transaction failed', err);
              return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Booking successful' });
          });
        });
      });
    });
  });
});

app.get('/bookings', authenticateJWT, (req, res) => {
  db.query('SELECT * FROM Bookings WHERE user_id = ?', [req.user.id], (err, results) => {
    if (err) {
      console.error('Fetching bookings failed', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

app.get('/bookings/:id', authenticateJWT, (req, res) => {
  db.query('SELECT * FROM Bookings WHERE user_id = ? AND id = ?', [req.user.id, req.params.id], (err, results) => {
    if (err) {
      console.error('Fetching booking details failed', err);
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) return res.status(404).json({ message: 'Booking not found' });
    res.json(results[0]);
  });
});

app.get('/trains', authenticateJWT, (req, res) => {
  if (req.user.role !== 'Admin') return res.sendStatus(403);
  db.query('SELECT * FROM Trains', (err, results) => {
    if (err) {
      console.error('Fetching trains failed', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

app.put('/trains', authenticateJWT, (req, res) => {
  if (req.user.role !== 'Admin') return res.sendStatus(403);
  const { train_id, total_seats } = req.body;
  db.query('UPDATE Trains SET total_seats = ? WHERE id = ?', [total_seats, train_id], (err, results) => {
    if (err) {
      console.error('Updating train seats failed', err);
      return res.status(500).json({ error: err.message });
    }
    if (results.affectedRows === 0) return res.status(404).json({ message: 'Train not found' });
    res.json({ message: 'Seats updated successfully' });
  });
});
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM Users WHERE username = ?', [username], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
      const user = results[0];
      bcrypt.compare(password, user.password_hash, (err, match) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!match) return res.status(401).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, role: user.role }, 'secret_key');
        res.json({ token, role: user.role });
      });
    });
  });
  
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
