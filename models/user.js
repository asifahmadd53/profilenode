const mongoose = require('mongoose')

mongoose.connect('mongodb://localhost:27017/miniprojectpractice')

let userSchema = mongoose.Schema({
    username: String,
    name:String,
    email:String,
    password:String,
    profilepic:{
        type :String,
        default : "default.png"
    },
    post:[
        {type: mongoose.Schema.Types.ObjectId, ref: 'post'}
    ]
})

module.exports = mongoose.model('user',userSchema)