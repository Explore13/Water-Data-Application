import express from "express";
import { dirname } from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";

const app = express();
const port = 3000;

// Create a PostgreSQL connection pool
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "WaterAppUsers",
  password: "admin",
  port: 5432, // Default PostgreSQL port
});

db.connect();

// Middleware for parsing cookies
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Middleware for parsing request bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the 'public' directory
app.use(express.static("public"));

// Salt rounds for password hashing
const saltRounds = 10;

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.cookies.contact) {
    next();
  } else {
    res.redirect("/login");
  }
};

// Route to serve the home page
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/homePage.html");
});

// Route to serve the water data page (requires authentication)
app.get("/waterData", isAuthenticated, (req, res) => {
  res.sendFile(__dirname + "/public/waterData.html");
});

// Route to serve the login page
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

// Route to serve the registration page
app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/public/register.html");
});

// Route to serve the password reset page
app.get("/resetpassword", (req, res) => {
  res.sendFile(__dirname + "/public/updatePage.html");
});

// Route to handle user login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userData = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (userData.rows.length > 0) {
      const hashedPassword = userData.rows[0].password;
      bcrypt.compare(password, hashedPassword, (err, result) => {
        if (result) {
          res.cookie("contact", userData.rows[0].mobile_number); // Set contact cookie upon successful login
          res.redirect("/waterData");
        } else {
          res.redirect("/login?passwordMismatch=true");
        }
      });
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Route to handle password reset
app.post("/resetpassword", async (req, res) => {
  const email = req.body.username;
  const secretCode = req.body.secretcode;
  const newPass = req.body.newpass;
  console.log(
    "Input Email: " + email + "\nNew Password: " + newPass + "\nSecret Code: " + secretCode
  );

  try {
    // Check if the user with the provided email exists
    const checkUserData = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkUserData.rows.length > 0) {
      // User exists, now check if the secret code matches
      const storedCode = checkUserData.rows[0].secretcode;

      if (secretCode === storedCode) {
        // Secret code matches, proceed to update the password
        bcrypt.hash(newPass, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing new password:", err);
            res.status(500).send("Internal Server Error");
          } else {
            try {
              // Update the password in the database
              await db.query("UPDATE users SET password = $1 WHERE email = $2", [hash, email]);
              console.log("Password updated successfully");
              res.redirect("/login"); // Redirect to login page after successful password update
            } catch (updateError) {
              console.error("Error updating password in database:", updateError);
              res.status(500).send("Internal Server Error");
            }
          }
        });
      } else {
        // Secret code doesn't match
        console.log("Secret Code mismatch");
        res.redirect("/resetpassword?codeMismatch=true");
      }
    } else {
      // User doesn't exist with the provided email
      console.log("User does not exist");
      res.redirect("/register"); // Redirect to register page if user doesn't exist
    }
  } catch (error) {
    console.error("Error resetting password:", error.message);
    res.status(500).send("Internal Server Error");
  }
});

// Route to handle user registration
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const pass = req.body.password;
  const fullName = req.body.fullName;
  const mobileNumber = req.body.mobile;
  const userCity = req.body.city;
  const secretCode = req.body.secretcode;
  console.log(
    `User Data comes from Client : ${email},${fullName},${mobileNumber},${userCity},${pass},${secretCode}`
  );

  try {
    const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkUser.rows.length > 0)
      res.send("User already exists. Try to login or create a new account.");
    else {
      bcrypt.hash(pass, saltRounds, async (err, hash) => {
        // Store hash in your password DB.
        const result = await db.query(
          "INSERT INTO users(email,password,user_name,mobile_number,city,secretcode) VALUES ($1,$2,$3,$4,$5,$6)",
          [email, hash, fullName, mobileNumber, userCity, secretCode]
        );
        console.log(result);
      });

      res.redirect("/login");
    }
  } catch (err) {
    res.send(err.message);
    console.log(err.message);
  }
});

// Route to fetch user data
app.get("/userData", isAuthenticated, async (req, res) => {
  const loggedInUser = req.cookies.contact;

  try {
    const userData = await db.query("SELECT * FROM users WHERE mobile_number = $1", [loggedInUser]);
    if (userData.rows.length > 0) {
      res.json(userData.rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Route to handle logout
app.get("/logout", (req, res) => {
  res.clearCookie("contact"); // Clear contact cookie upon logout
  res.redirect("/");
});

// Start the server
app.listen(port, () => {
  console.log("Server Connected Successfully");
});
