const jwt = require('jsonwebtoken')
const User = require('../models/UserModel')
const asyncHandler = require('express-async-handler')

const protect = asyncHandler(async (req, res, next) => {
    // Definimos la variable token
    let token

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Obtenemos el token del encabezado
            token = req.headers.authorization.split(' ')[1]
            // Verficar la firma y el token
            const decoded = jwt.verify(token, process.env.JWT_SECRET)

            // Voy a obtener los datos del usuario del token verificado
            req.user = await User.findById(decoded.id).select('-password')

            next()
        } catch (error) {
            console.log(error)
            res.status(401)
            throw new Error('Acceso no autorizado')
        }
    }
    if(!token){
        res.status(401)
        throw new Error('Acceso no autorizado, no se proporciono el token')
    }
})

module.exports = { protect }