const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt }= require('express-jwt');
require('dotenv').config()
const User = require('./Models/user')

mongoose.connect(process.env.URL_DB)

const app = express();

app.use(express.json());

const validateToken = expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] });
const signToken = _id => jwt.sign({ _id }, process.env.JWT_SECRET, { expiresIn: '3h' });

app.post('/register', async (req, res) => {
    const { body } = req;
    console.log(body);
    try {
        const isUser = await User.findOne({ email: body.email });
        if (isUser) {
            return res.status(400).json({
                error: 'Usuario existe'
            });
        }
        const salt = await bcrypt.genSalt();
        const hash = await bcrypt.hash(body.password, salt);
        const user = await User.create({
            email: body.email,
            password: hash,
            salt: salt
        })
        const jwtSigned = signToken(user._id);
        res.status(201).send(jwtSigned);
    } catch (error) {
        console.log(error);
        res.status(500).send(error.message);
    }
})

app.post('/login', async (req, res) => {
    const { body } = req;
    try {
        const user = await User.findOne({ email: body.email });
        if (!user) {
            res.send('Usuario o contraseña incorrectos');
        }else{
            const isMatch = await bcrypt.compare(body.password, user.password); // Primer dato recibe contraseña no encryptada y el segundo la contraseña encryptada y regresa una promesa
            if (isMatch) {
                const jwtSigned = signToken(user._id);
                res.status(200).send(jwtSigned);
            }else{
                res.status(403).send('Usuario o contraseña incorrectos');
            }
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
})

const findAndAssignUser = async (req, res, next) => {
    try{
        const user = await User.findById(req.auth._id)
        if(!user){
            return res.status(401).end();
        }
        req.user = user
        next()
    }catch(error){
        res.status(500).send(error.message);
    }
}

const isAuthenticated = express.Router().use(validateToken, findAndAssignUser); //Centralizacion de middleware

app.get('/validate', isAuthenticated , (req, res) => {
    throw new Error('Error de prueba');
    res.send(req.user)
})
app.use((err, req, res, next) => {
    console.log('Manejo de errores', err.stack);
    next(err);
    res.status(500).send(err.message);
})
app.use((err, req, res, next) => {
    res.send('Ocurrio un error')
})

app.listen(3000, () => {
    console.log('Server on port 3000');
})