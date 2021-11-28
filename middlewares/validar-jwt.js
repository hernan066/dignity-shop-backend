const { response } = require('express');
const jwt = require('jsonwebtoken');

const validarJWT = (req, res = response, next) => {
    
    const token = req.headers['x-token'];
    
    if (!token) {
        return res.status(401).json({ 
            ok: false, 
            message: 'No hay token.' 
        });
    }
   try {
       const {uid, username} = jwt.verify(token, process.env.JWT_SEC);
       
        req.uid = uid;
        req.username = username;

       
   } catch (error) {
       return res.status(401).json({
            ok: false,
            message: 'Token no valido.'
         });
   }
    next();
}

module.exports = {
    validarJWT
};