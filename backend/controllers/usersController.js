const jwt = require('jsonwebtoken')
const bcryptjs = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/UserModel')

const login = asyncHandler(async (req, res) => {
    const { email, password } = req.body

    // Verificamos si el user existe
    const user = await User.findOne({ email })

    if(user && (await bcryptjs.compare(password, user.password))){
        res.status(200).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generarToken(user._id)
        })
    } else {
        res.status(400)
        throw new Error('Invalid credentials')
    }
})

const register = asyncHandler(async (req, res) => {

    const { name, email, password } = req.body

    if(!name || !email || !password){
        res.status(400)
        throw new Error('Please add all fields')
    }

    // Verificamos que el usuario no existe
    const userExist = await User.findOne({ email })
    if(userExist){
        res.status(400)
        throw new Error('User already exists')
    }

    // Hash al password
    const salt = await bcryptjs.genSalt(10)
    const hashedPassword = await bcryptjs.hash(password, salt)

    // Crear al usuario
    const user = await User.create({
        name,
        email,
        password: hashedPassword
    })

    if(user){
        res.status(201).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            // token: generateToken(user._id)
        })
    } else {
        res.status(400)
        throw new Error('Invalid user data')
    }

})

const data = asyncHandler(async (req, res) => {
    res.status(200).json(req.user)

})

const generarToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d'
    })
}

module.exports = {
    login,
    register,
    data
} 