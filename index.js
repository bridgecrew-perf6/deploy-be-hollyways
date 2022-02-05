require("dotenv").config()

const express = require("express");

const cors = require('cors')

// import socket.io
const http = require('http')
const {Server} = require('socket.io')

const app = express();

const server = http.createServer(app)
// const io = new Server(server, {
//  cors: {
//    origin: 'http://localhost:3000' // define client origin if both client and server have different origin
//  }
// })

// require('./src/socket')(io)

const router = require("./src/routes");

const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors())

app.use("/api/v1/", router);

app.use("/uploads", express.static("uploads"))

// app.use(function (err, req, res, next) {
//   console.log('This is the invalid field ->', err.field)
//   next(err)
// })

app.listen(port, () => console.log(`Listening on port ${port}!`));