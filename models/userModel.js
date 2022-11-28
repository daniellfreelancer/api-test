const mongoose = require('mongoose')




const schema = new mongoose.Schema({
    name : { type: String, required: true},
    email : {type: String, required: true},
    password: [{ type: String, required: true}],
    from: [{ type: String, required: true}],
    code: {type: String, required: true},
    role: {type: String, required: true},
    logged: {type: Boolean, required: true},
    verified: {type: Boolean, required: true}
})


const USERMODEL = mongoose.model(
    'users',
    schema
)

module.exports = USERMODEL;