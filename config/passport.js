const passport = require('passport')
const passportJWT = require('passport-jwt')

const {KEY_JWT} = process.env
const User = require('../models/userModel')

passport.use(
    new passportJWT.Strategy(
        {                                 
            jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: KEY_JWT
        },
        async (jwt_payload, done) =>{

            try {
                let user = await User.findOne({_id:jwt_payload.id})
                if(user){
                    user = {
                        _id: user._id,
                        name: user.name,
                        email: user.email,
                        role: user.role,
                    }
                    return done(null, user)
                }else{
                    return done(null, false)
                }
            } catch (error) {
                console.log(error)
                return done(error, false)
            }
        }
    )
)
module.exports = passport