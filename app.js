require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

//rota pública
app.get('/', (req, res) => {
    res.status(200).json({msg:"Bem vindo a nossa API!"})
})

//rota privada
app.get("/user/:id",checkToken, async(req, res) => {
    const id = req.params.id

    const user = await User.findById(id, '-senha')

    if(!user){
        return res.status(404).json({msg: "usuario não encontrado"})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg: "Acesso negado!"})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch (error) {
        res.status(400).json({msg: "Token inválido"})
    }
}

app.post('/auth/register', async(req,res) => {

    const {email,senha,confirmeSenha} = req.body

    if(!email){
        return res.status(422).json({msg: "o email é obrigatório!"})
    }
    if(!senha){
        return res.status(422).json({msg: "a senha é obrigatório!"})
    }
    if(senha !== confirmeSenha){
        return res.status(422).json({msg: "as senha não conferem"})
    }

    const userExiste = await User.findOne({email : email})

    if(userExiste){
        return res.status(422).json({msg: "Por favor, utilize outro email"})
    }

    const salt = await bcrypt.genSalt(12)
    const senhaHash = await bcrypt.hash(senha, salt)

    const user = new User({
        email,
        senha: senhaHash
    })

    try {
        await user.save()

        res.status(201).json({msg: "usuario criado com sucesso!!"})

    }catch(err){
        console.log(error)
        res.status(500).json({msg:"ocorreu um erro no servidor, tente novamente mais tarde!",})

    }
})

app.post("/auth/login", async (req, res) => {

    const {email, senha} = req.body

    if(!email){
        return res.status(422).json({msg: "o email é obrigatório!"})
    }
    if(!senha){
        return res.status(422).json({msg: "a senha é obrigatória!"})
    }

    //ver se o usuario existe
    const user = await User.findOne({email : email})

    if(!user){
        return res.status(404).json({msg: "Usuario não encontrado!"})
    }

    //checar se a senha está correta
    const checkSenha = await bcrypt.compare(senha, user.senha)

    if(!checkSenha){
        return res.status(422).json({msg: "Senha inválida!"})
    }

    try{

        const secret = process.env.SECRET

        const token = jwt.sign(
        {
            id: user._id,
        },
        secret,
    )

    res.status(200).json({msg: "Autenticação realizada com sucesso!!", token})

    }catch(err) {
        console.log(error)
        res.status(500).json({msg:"ocorreu um erro no servidor, tente novamente mais tarde!",})
    }

})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@authjwt.cuhqw5s.mongodb.net/?retryWrites=true&w=majority&appName=authjwt`,).then(() => {
    app.listen(3000)
    console.log("conectou ao banco!")
}).catch((err) => console.log(err))

