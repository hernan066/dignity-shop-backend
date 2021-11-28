const jwt = require('jsonwebtoken');

const generarJWT = (uid, username) => {

    return new Promise((resolve, reject) => {

        const payload = {
            uid,
            username
        };

        jwt.sign(payload, process.env.JWT_SEC, {
            expiresIn: '4h'
        }, (err, token) => {
            if (err) {
                reject('Error generando el token');
            } else {
                resolve(token);
            }
        });
    });

}

module.exports = {
    generarJWT
}