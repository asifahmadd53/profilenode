const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const userModel = require('./models/user');
const postModel = require('./models/post')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const user = require('./models/user');
const path = require('path')
const multerConfig = require('./config/multerconfig.js')


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname,'public')))
app.use(cookieParser());


app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/signup', async (req, res) => {
    const { username, name, email, password } = req.body;

    let findUser = await userModel.findOne({ email });
    if (findUser) {
        return res.status(400).send({ message: 'Email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = await userModel.create({
        username,
        name,
        email,
        password: hash
    });

    const token = jwt.sign({ email, userid: user._id }, 'shhh');
    res.cookie('token', token);
    
    // Redirect to the login page
    res.redirect('/login');
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loginacc', async (req, res) => {
    let { email, password } = req.body;

    let findUser = await userModel.findOne({ email });
    if (!findUser) {
        return res.status(400).send({ message: "Invalid email or password" });
    }

    bcrypt.compare(password, findUser.password, (err, result) => {
        if (err) {
            return res.status(500).send({ message: "Internal server error" });
        }
        
        if (result) {
            let token = jwt.sign({ email, userid: findUser._id }, 'shhh');
            res.cookie('token', token);
            return res.status(200).redirect("/profile");
        } else {
            return res.status(400).send({ message: "Invalid email or password" });
        }
    });
});

function isLoggedIn(req, res, next) {
    const token = req.cookies?.token;
    if (!token) {
        return res.redirect('/login');
    }

    try {
        let data = jwt.verify(token, 'shhh');
        req.user = data;
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/login');
    }
}

app.get('/profile', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({email: req.user.email}).populate('post')
    res.render('profile', {user});
});

app.post('/post', isLoggedIn ,async (req, res)=>{
    let user = await userModel.findOne({email: req.user.email})
    let {content} = req.body
    let post = await postModel.create({
        user: user._id,
        content,
    })
    user.post.push(post._id)
    await user.save()
    res.redirect('/profile')
})

app.get('/like/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id }).populate('user');
    
    // Check if the user has already liked the post
    if (post.likes.indexOf(req.user.userid) === -1) {
        post.likes.push(req.user.userid); // Add like
    } else {
        post.likes.splice(post.likes.indexOf(req.user.userid), 1); // Remove like
    }
    
    await post.save();
    res.redirect('/profile');
});


app.get('/edit/:id', isLoggedIn, async (req, res)=>{
    let post = await postModel.findOne({_id: req.params.id }).populate('user');
    res.render('edit',{post} ); 
})

app.post('/update/:id', async(req, res)=>{
    let post = await postModel.findOneAndUpdate({_id: req.params.id}, {content: req.body.content})
    res.redirect('/profile')
})

const port = process.env.PORT || 4000;

app.listen(port, () => {
    console.log(`Server is running on port http://localhost:${port}`);
});
