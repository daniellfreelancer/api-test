const User = require('../models/userModel');
const Joi = require('joi');
const crypto = require('crypto')
const bycryptjs = require('bcryptjs');
const sendMailToActivate = require('../mails/sendMailToActivate');
const jwt = require('jsonwebtoken')

const signupValidator = Joi.object({
    "name": Joi.string().messages({
        'string.empty': 'Por favor, escriba su nombre'
    }).required(),
    "email": Joi.string().email().message({
        'string.empty': 'Escriba su correo electrónico',
        'string.email': 'Debe introducir una dirección de correo electrónico válida'
    }).required(),
    "password": Joi.string().alphanum().min(6).messages({
        'string.empty': 'Escriba una contraseña',
        'string.alphanum': 'Debe introducir una contraseña que contenga números o letras',
        'string.min': 'Su contraseña debe tener al menos 6 caracteres '
    }).required(),
    "from": Joi.string().required(),
    "role": Joi.string(),
})

const signinValidator = Joi.object({
    "email": Joi.string()
        .email()
        .required(),
    "password": Joi.string()
        .required(),
    "from": Joi.string().required()
})

const userController = {

    signUp: async (request, response) => {
        let {
            name,
            email,
            password,
            role,
            from
        } = request.body;

        try {
            await signupValidator.validateAsync(request.body);
            let user = await User.findOne({email});

            if(!user){
                
                let logged = false;
                let verified = false;
                let code = crypto.randomBytes(15).toString('hex');
                
                if ( from === 'form') {
                    console.log("sent mail to activate");
                    sendMailToActivate(email, code, name)
                } else {
                    verified = true;
                }

                password = bycryptjs.hashSync(password, 10);
                user = await new User({
                    name,
                    email,
                    password: [password],
                    role,
                    from: [from],
                    logged,
                    verified,
                    code
                }).save()
                response.status(201).json({
                    message: "Usuario registrado con exito",
                    success: true
                })
            } else {

                if(user.from.includes(from)) {
                    response.status(200).json({
                        message: "El usuario ya existe, se creó desde: " + from,
                        success: true
                    })
                } else {
                    user.from.push(from);
                    user.verified = true;
                    user.password.push(bycryptjs.hashSync(password, 10));
                    await user.save();
                    response.status(201).json({
                        message: "El usuario ha sido registrado con exito desde: " + from,
                        success: true
                    })
                }
            }
            
        } catch (error) {
            console.log(error);
            response.status(400).json({
                message: error.message,
                success: false
            })
            
        }
    },
    signIn: async (request, response) => {

        const { 
            email, 
            password, 
            from 
        } = request.body;

        try {
            
            await signinValidator.validateAsync(request.body);
            const user = await User.findOne({email});

            const token = jwt.sign(
                {
                    id: user._id,
                    role: user.role
                },
                process.env.KEY_JWT,
                {
                    expiresIn: 60 * 60 * 24
                }
            )
            if(!user) {
                response.status(404).json({
                    message: "El usuario no existe, por favor regístrese",
                    success: false
                })
            } else if( user.verified){
                
                const userPass = user.password.filter(uPass => bycryptjs.compareSync(password, uPass));

                if ( from === "form"){
                    if(userPass.length > 0) {
                        const loginUser = {
                            name : user.name,
                            email: user.email,
                            role: user.role
                        }
                        user.logged = true;
                        await user.save()

                        response.status(200).json({
                            message: 'Inicio de sesion con exito',
                            success: true,
                            res: {
                                user: loginUser,
                                token: token
                            }
                        })
                    } else {
                        response.status(400).json({
                            message: "Error al iniciar sesion, por favor verifique su correo y/o contraseña"
                        })
                    }
                } else {
                    if(userPass.length > 0) {
                        const loginUser = {
                            name : user.name,
                            email: user.email,
                            role: user.role
                        }
                        user.logged = true;
                        await user.save()

                        response.status(200).json({
                            message: 'Inicio de sesion con exito desde google',
                            success: true,
                            res: {
                                user: loginUser,
                                token: token
                            }
                        })
                    }
                }

            }   else {
                response.status(401).json({
                    message: 'Fallo en el inicio de sesión, por favor verifique su correo electrónico',
                    success: false
                })
            }


        } catch (error) {
            console.log(error);
            response.status(400).json({
                message: error.message,
                success: false
            })
        }


    },
    signOut: async(request, response) => {
        const { email } = request.body;

        try {
            const user = await User.findOne({ email});
            if (user) {
                
                user.logged = false;
                await user.save();

                response.status(200).json({
                    message:" Te has deslogueado correctamente",
                    success: true,
                    res: user.logged
                })

            } else {
                response.status(400).json({
                    message:"No estas logueado, por ende no puedes desloguearte",
                    success: false
                })
            }

        } catch (error) {
            console.log(error);
            response.status(400).json({
                message: "Error al cerrar sesión",
                success: false
            })
        }
    },
    userVerify : async (request, response) => {
        const { code } = request.params;

        try {
            
            const user = await User.findOne({code});

            if(user){
                user.verified = true;
                await user.save();
                response.status(200).json({
                    message: 'Tu cuenta ha sido activada con exito',
                    success: true
                })
            } else {
                response.status(404).json({
                    message: "Email no esta registrado",
                    success: false
                })
            }


        } catch (error) {
            console.log(error);
            response.status(400).json({
                message: "Account mail could not be verified",
                success: false
            })
        }
    },
    signInWithToken: (request, response) => {
        const token = jwt.sign({
            id: request.user._id
        },
        process.env.KEY_JWT,
        { expiresIn: 60 * 60 * 24 }
        )

        if(request.user !== null) {
            response.status(200).json({
                success: true,
                response: { 
                    user: request.user, 
                    token: token 
                },
                message: 'Welcome ' + request.user.name + '!'
            })
        } else {
            response.status(400).json({
                success: false,
                message: 'error'
            })
        }
    },
    editProfile: async (request, response) => {
        const { id } = request.params
        try {
            const newDataProfile = request.body
            let user = await User.findOne({ _id: id })
            if (user) {
                const updateProfile = await User.findByIdAndUpdate(id, newDataProfile)
                response.status(200).json({
                    message: 'Tu perfil se ha actualizado',
                    success: true
                })
            }
        } catch (error) {
            console.log(error)
            response.status(400).json({
                message: error.message,
                success: false
            })
        }
    }

}


module.exports = userController;

