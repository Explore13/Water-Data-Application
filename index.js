import express from "express";
import { dirname } from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

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

app.use(bodyParser.urlencoded({ extended: true }));
const __dirname = dirname(fileURLToPath(import.meta.url));
app.use(express.static("public"));
const saltRounds = 10;

app.get("/", (req, res) => {
  // console.log(__dirname + "/public/homePage.html");
  res.sendFile(__dirname + "/public/homePage.html");
});

app.get("/login", (req, res) => {
  // console.log(__dirname + "/public/login.html");
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/register", (req, res) => {
  // console.log(__dirname + "/public/homePage.html");
  res.sendFile(__dirname + "/public/register.html");
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const pass = req.body.password;
  console.log("Input Email : " + email + "\nInput Password : " + pass);

  try {
    const checkUserData = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    console.log(checkUserData.rows);
    if (checkUserData.rows.length > 0) {
      const storedPass = checkUserData.rows[0].password;
      console.log("\nPassword in DB : " + storedPass);
      bcrypt.compare(pass, storedPass, (err, result) => {
        console.log(result);
        if (err) {
          console.log("Error password matching", err.message);
        } else {
          if (result) {
            console.log("Password Matched");
            res.sendFile(__dirname + "/public/waterData.html");
        } else {
            console.log("Password mis-matched");
            // res.sendFile(__dirname + "/public/login.html");
            res.redirect('/login?passwordMismatch=true');
        }
        }
      });
    } else {
      res.send("Users does not exist");
    }
  } catch (error) {
    res.send(err.message);
  }
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const pass = req.body.password;
  const fullName = req.body.fullName;
  const mobileNumber = req.body.mobile;
  const userCity = req.body.city;
  console.log(
    `User Data comes from Client : ${email},${fullName},${mobileNumber},${userCity},${pass}`
  );

  try {
    const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkUser.rows.length > 0)
      res.send("User already exists. Try to login or create a new account.");
    else {
      bcrypt.hash(pass, saltRounds, async (err, hash) => {
        // Store hash in your password DB.
        const result = await db.query(
          "INSERT INTO users(email,password,user_name,mobile_number,city) VALUES ($1,$2,$3,$4,$5)",
          [email, hash, fullName, mobileNumber, userCity]
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

app.listen(port, () => {
  console.log("Server Connected Succesfully");
});
