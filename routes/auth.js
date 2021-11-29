/* const router = require("express").Router();
const User = require("../models/User");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

//REGISTER
router.post("/register", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: CryptoJS.AES.encrypt(
      req.body.password,
      process.env.PASS_SEC
    ).toString(),
  });

  try {
    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).json(err);
  }
});

//LOGIN

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({
      userName: req.body.user_name,
    });

    !user &&
      res.status(401).json({
        ok: false,
        msg: "El usuario no existe con ese email",
      });

    const hashedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SEC
    );

    const originalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

    const inputPassword = req.body.password;

    originalPassword != inputPassword &&
      res.status(401).json({
        ok: false,
        msg: "Contraseña incorrecta",
      });
    
      //Generar token
    const accessToken = jwt.sign(
      {
        id: user._id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SEC,
      { expiresIn: "3d" }
    );

    const { password, ...others } = user._doc;
    res.status(200).json({
      ...others,
      accessToken
      
    });
  } catch (err) {
    res.status(500).json(err);
  }
});

module.exports = router; */

const express = require("express");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { generarJWT } = require("../helpers/jwt");
const { validarJWT } = require("../middlewares/validar-jwt");

const router = require("express").Router();



//////////////////////////////////////////////////////////////
const crearUsuario = async (req, res = express.response) => {
  /* console.log(req.body); */

  const { username, email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({
        ok: false,
        msg: "El email ya esta en uso",
      });
    }

     user = new User(req.body);
    
    //Encriptar contraseña 
    const salt = bcrypt.genSaltSync();
    user.password = bcrypt.hashSync(password, salt);
    
     await user.save();

     //Generar token
      const token = await generarJWT(user.id,  user.username);

    return res.status(201).json({
      ok: true,
     uid: user.id,
     username: user.username,
     token
    });
  
   } catch (error) {
    console.log(error);
    res.status(500).json({
      ok: false,
      msg: "Por favor hable con el admin",
    });
  }
};





////////////////////////////////////////////////////////////
const login = async(req, res = express.response) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    console.log(user);

    if (!user) {
      return res.status(400).json({
        ok: false,
        msg: "El usuario no existe con ese email",
      });
    } 

    //Confirmar contraseña

    const validPassword = bcrypt.compareSync(password, user.password);
    
    if(!validPassword){
      return res.status(400).json({
        ok: false,
        msg: "Contraseña incorrecta",
      });
    }
    //Generar token
    const token = await generarJWT(user.id,  user.username);
    
    res.json({
      ok: true,
      uid: user.id,
      username: user.username,
      isAdmin: user.isAdmin,
      token
    });



    
  } catch (error) {
    console.log(error);
    res.status(500).json({
      ok: false,
      msg: "Por favor hable con el admin",
    });
    
  }
  
 
};



////////////////////////////////////////////////////
const renewToken = async (req, res = express.response) => {
 
  const {uid, username} = req;
  
  

  //generar token
  const token = await generarJWT(uid, username);
  

  res.json({
    ok: true,
    uid,
    username,
    isAdmin,
    token
  });
};

/* module.exports = {
  crearUsuario: crearUsuario,
  login: login,
  renewToken: renewToken,
}; */

router.post("/login", login);
router.post("/register", crearUsuario);
router.get("/renew", validarJWT, renewToken);



module.exports = router;
