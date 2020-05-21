require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(bodyParser.json());
const users = [];
let refreshTokens = [];
const posts = [
  {
    name: "Kyle",
    title: "post 1",
  },
  {
    name: "gurkaran",
    title: "post 2",
  },
];
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.send("token is null");
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.send("token can't be verified");
    req.user = user;
    next();
  });
}
app.get("/users", (req, res) => {
  res.json(users);
});

app.post("/users", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const user = { name: req.body.name, password: hashedPassword };
    users.push(user);
    res.sendStatus(201).send();
  } catch {
    res.sendStatus(500).send();
  }
});
app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});
app.get("/posts", authenticate, (req, res) => {
  res.json(posts.filter((post) => post.name === req.user.name));
});
app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.send({ accessToken: accessToken });
  });
});
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "25s" });
}
app.post("/users/login", async (req, res) => {
  //Authentication...
  const user = users.find((u) => u.name === req.body.name);
  if (user == null) {
    return res.send("Cannot Find User");
  } else {
    try {
      if (await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken({ name: req.body.name });
        const refreshToken = jwt.sign(
          { name: req.body.name },
          process.env.REFRESH_TOKEN_SECRET
        );
        refreshTokens.push(refreshToken);
        res.json({ accessToken: accessToken, refreshToken: refreshToken });
      } else {
        res.send("password wrong");
      }
    } catch {
      res.sendStatus(500).send();
    }
  }
});

app.listen(3000);
