const { createHash } = require("crypto");
const url = require("url");

const express = require("express");
const bp = require("body-parser");
const axios = require("axios");
const jwt = require("jwt-simple");

const secret = require("./secret.json");

const app = express();
app.use(bp.json());

const salt = "hakatanosalt";

app.get("/oauth/callback", (req, res) => {
  console.log(
    JSON.stringify({
      code: req.query.code,
      state: req.query.state
    })
  );
  res.send("ok");
});

app.get("/oauth/google/login", function(req, res) {
  const state = createHash("sha256")
    .update(`${salt}${Math.random()}${+new Date()}`)
    .digest("hex");
  const params = new url.URLSearchParams({
    response_type: "code",
    client_id: secret.clientId,
    redirect_uri: "https://localhost:3000/oauth/callback",
    scope: "profile",
    state
  });
  // ここでstateをセッションに格納するなりしよう
  res.redirect(
    303,
    `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
  );
});

app.post("/oauth/google/authorize", (req, res) => {
  // curlで確認しているためセッションが確認つかえないので一旦スキップ。本番環境で運用する場合は必ずstateの検証をやること
  // if (state !== req.body.state) {
  //   res.send(400);
  // }
  console.log("poe");
  auth(req)
    .then(a => {
      res.send("a");
    })
    .catch(err => {
      console.dir(err);
      res.send("err");
    });
});

const decodeBase64 = str => Buffer.from(str, "base64").toString("utf8");
async function auth(req) {
  const idToken = (await axios.post(secret.tokenUrl, {
    client_id: secret.clientId,
    client_secret: secret.clientSecret,
    redirect_uri: "https://localhost:3000/oauth/callback",
    grant_type: "authorization_code",
    code: req.body.code
  })).data.id_token;
  const segments = idToken.split(".") || "";
  if (segments.length <= 2) {
    return Promise.reject("segmentの長さおかしい");
  }
  const envelope = JSON.parse(decodeBase64(segments[0]));
  if (envelope.kid === undefined) {
    return Promise.reject("kid?");
  }
  const payload = JSON.parse(decodeBase64(segments[1]));

  console.dir(envelope.kid);
  const certs = (await axios.get("https://www.googleapis.com/oauth2/v3/certs"))
    .data;
  const key = certs.keys.find(val => val.kid === envelope.kid);
  console.dir(jwt.decode(idToken, key.n, key.alg));
  return "";
}

app.listen(3000, function() {
  console.log("Example app listening on port 3000!");
});
