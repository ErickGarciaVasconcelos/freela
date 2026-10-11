const mongoose = require("mongoose");
const dotenv = require("dotenv");
const express = require("express");

dotenv.config();

const mongoDB = process.env.MONGODB_URI || "mongodb://localhost:27017/freela-seguro";
const JWT_SECRET = process.env.JWT_SECRET || "chave_super_secreta_desenvolvimento";

mongoose.connect(mongoDB);

const app = express();
app.use(express.json());

// Import middleware
const autenticarToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ erro: "Token não fornecido" });
    try {
        const jwt = require("jsonwebtoken");
        req.usuarioLogado = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        res.status(403).json({ erro: "Token inválido" });
    }
};

// Import schemas
const Usuario = require("./models/Usuario");
const Vaga = require("./models/Vaga");

// Test endpoint
app.get("/teste", (req, res) => {
    res.json({ mensagem: "Servidor de teste rodando" });
});

app.listen(3001, () => console.log("Servidor de teste na porta 3001"));
