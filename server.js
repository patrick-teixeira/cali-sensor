const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const initializePassport = require('./passport-config');
const pool = require('./database');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); 
const mysql = require('mysql2/promise'); 
const Highcharts = require('highcharts');

const app = express();


initializePassport(passport, 
    email => {
        pool.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
            if (err) {
                console.error('Erro ao buscar usuário:', err);
                return null;
            }
            return result[0]; 
        });
    },
    id => {
        pool.query('SELECT * FROM usuarios WHERE idusuarios = ?', [id], (err, result) => {
            if (err) {
                console.error('Erro ao buscar usuário:', err);
                return null;
            }
            return result[0]; 
        });
    }
);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.use("/uploads", express.static('uploads'));


app.get('/navbar-before-login', (req, res) => {
    res.render('navbar-before-login.ejs');
});


app.get('/navbar-after-login', (req, res) => {
    res.render('navbar-after-login.ejs');
});


function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        console.log('Usuário autenticado, redirecionando para página inicial');
        return res.redirect('/');
    } else {
        console.log('Usuário não autenticado, permitindo acesso à rota');
        next();
    }
}


app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { title: 'Título da Página', name: req.user.nome });
});



app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});


app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));


app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});


app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        pool.query('INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)', 
            [req.body.name, req.body.email, hashedPassword], 
            (err, result) => {
                if (err) {
                    console.error('Erro ao inserir usuário:', err);
                    res.redirect('/register');
                    return;
                }
                console.log('Usuário inserido com sucesso:', result);
                res.redirect('/login');
            });
    } catch (error) {
        console.error(error);
        res.redirect('/register');
    }
});

app.post('/register-flexao', async (req, res) => {
    try {
        const { userId, quantFlexoes, email} = req.body;
        if (!userId || !quantFlexoes || !email) {
            res.status(400).json({ message: 'Campos incompletos' });
            return;
        }
        const dataAtual = new Date();
        const ano = dataAtual.getFullYear();
        const mes = String(dataAtual.getMonth() + 1).padStart(2, '0'); 
        const dia = String(dataAtual.getDate()).padStart(2, '0');
        const dataFlexao = `${ano}-${mes}-${dia}`;
        horaFlexao = dataAtual.toLocaleTimeString('pt-BR', { hour12: false });
        pool.query('INSERT INTO flexoes (idusuarios, data, quant_flexoes, email, data_flexao, hora_flexao) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, dataFlexao, quantFlexoes, email, dataFlexao, horaFlexao],
            (err, result) => {
                if (err) {
                    console.error('Erro ao inserir flexão:', err);
                    res.status(500).json({ message: 'Erro ao inserir flexão' });
                    return;
                }
                console.log('Flexão inserida com sucesso:', result);
                res.status(200).json({ message: 'Flexão registrada com sucesso' });
            });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});




app.get('/delete-account', checkAuthenticated, (req, res) => {
    res.redirect('/login');
});


app.delete('/delete-account', checkAuthenticated, async (req, res) => {
    try {
        const userId = req.user.idusuarios;
        if (!userId) {
            console.error('ID do usuário não encontrado');
            return res.status(500).send('ID do usuário não encontrado');
        }
        pool.query('DELETE FROM usuarios WHERE idusuarios = ?', [userId], (err, result) => {
            if (err) {
                console.error('Erro ao deletar usuário:', err);
                return res.status(500).send('Erro ao deletar usuário');
            }
            if (result.affectedRows === 0) {
                console.error('Nenhum usuário encontrado para excluir com o ID:', userId);
                return res.status(404).send('Usuário não encontrado para excluir');
            }
            console.log('Usuário deletado com sucesso:', result);
            req.logout(function(err) {
                if (err) {
                    console.error('Erro ao fazer logout:', err);
                    return res.status(500).send('Erro ao fazer logout');
                }
                req.session.destroy(function(err) {
                    if (err) {
                        console.error('Erro ao destruir a sessão:', err);
                        return res.status(500).send('Erro ao destruir a sessão');
                    }
                    
                    res.json({ success: true, redirectUrl: '/login' });
                });
            });
        });
    } catch (error) {
        console.error('Erro ao deletar usuário:', error);
        res.status(500).send('Erro ao deletar usuário');
    }
});



app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Erro ao fazer logout:', err);
            return res.redirect('/');
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Erro ao destruir a sessão:', err);
                return res.redirect('/');
            }
            res.redirect('/login');
        });
    });
});


app.get('/forgot-password', (req, res) => {
    res.render('forgot-password.ejs');
});


app.post('/forgot-password', async (req, res) => {
    try {
        const [user] = await pool.promise().query('SELECT * FROM usuarios WHERE email = ?', [req.body.email]);

        if (user.length === 0) {
            req.flash('error', 'Email não encontrado');
            return res.redirect('/forgot-password');
        }

        const token = crypto.randomBytes(20).toString('hex');

        await pool.promise().query('UPDATE usuarios SET reset_password_token = ?, reset_password_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR), link_utilizado = FALSE WHERE email = ?', [token, req.body.email]);

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.EMAIL,
                pass: 'wuepvqvcfxfsnzjf'
            }
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: req.body.email,
            subject: 'Link para redefinição de senha',
            text: `Você está recebendo este email porque solicitou a redefinição de senha.\n\nClique neste link ou copie e cole no seu navegador para redefinir sua senha:\n\nhttp://${req.headers.host}/reset-password/${token}\n\nSe você não solicitou isso, ignore este email e sua senha permanecerá inalterada.`
        };

        await transporter.sendMail(mailOptions);

        req.flash('success', 'Email enviado com sucesso! Verifique sua caixa de entrada para redefinir sua senha.');
        res.redirect('/forgot-password');
    } catch (error) {
        console.error('Erro ao processar solicitação de redefinição de senha:', error);
        req.flash('error', 'Erro ao processar solicitação de redefinição de senha');
        res.redirect('/forgot-password');
    }
});



app.get('/reset-password/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const [user] = await pool.promise().query('SELECT * FROM usuarios WHERE reset_password_token = ? AND reset_password_expires > NOW()', [token]);
        if (user.length === 0) {
            req.flash('error', 'Link de redefinição de senha inválido ou expirado');
            return res.redirect('/forgot-password');
        }
        
        
        res.render('reset-password.ejs', { token: token, error: req.flash('error'), success: req.flash('success') }); // Passa o sucesso e o erro para a página

    } catch (error) {
        console.error('Erro ao processar redefinição de senha:', error);
        req.flash('error', 'Erro ao processar redefinição de senha');
        res.redirect('/forgot-password');
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const [user] = await pool.promise().query('SELECT * FROM usuarios WHERE reset_password_token = ? AND reset_password_expires > NOW()', [token]);
        if (user.length === 0) {
            req.flash('error', 'Link de redefinição de senha inválido ou expirado');
            return res.redirect('/forgot-password');
        }

        
        if (user[0].link_utilizado) {
            req.flash('error', 'Link de redefinição de senha já foi utilizado');
            return res.redirect('/forgot-password');
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
   
        await pool.promise().query('UPDATE usuarios SET senha = ?, reset_password_token = NULL, reset_password_expires = NULL, link_utilizado = TRUE WHERE reset_password_token = ?', [hashedPassword, token]);
        req.flash('success', 'Senha redefinida com sucesso! Faça login com sua nova senha.');
        res.redirect('/login');
    } catch (error) {
        console.error('Erro ao processar redefinição de senha:', error);
        req.flash('error', 'Erro ao processar redefinição de senha');
        res.redirect('/forgot-password');
    }
});


app.get('/dashboard', checkAuthenticated, async (req, res) => {
    try {
        
        const userId = req.user.idusuarios;
        const [flexoes] = await pool.promise().query('SELECT email, quant_flexoes FROM flexoes WHERE idusuarios = ?', [userId]);

        
        res.render('dashboard', { title: 'Dashboard', flexoes: JSON.stringify(flexoes), user: req.user });
    } catch (error) {
        console.error('Erro ao buscar dados de flexões:', error);
        res.status(500).send('Erro ao buscar dados de flexões');
    }
});

app.get('/dados-flexoes', checkAuthenticated, async (req, res) => {
    try {
        const userId = req.user.idusuarios;
        console.log(userId)
        const [flexoes] = await pool.promise().query('SELECT email, quant_flexoes FROM flexoes WHERE idusuarios = ?', [userId]);
        
        // let totalFlexoes = 0;

        // // Iterar sobre as flexões para calcular o total de flexões
        // flexoes.forEach(flexao => {
        //     totalFlexoes += flexao.quant_flexoes;
        // });

        // // Adicionar o total de flexões ao objeto JSON
        // const flexoesComTotal = {
        //     ...flexoes,
        //     total_flexoes: totalFlexoes
        // };

        res.json(flexoes); 
    } catch (error) {
        console.error('Erro ao buscar dados de flexões:', error);
        res.status(500).send('Erro ao buscar dados de flexões');
    }
});

app.get('/rankingg', async(req, res) => {
    try {
        const query = 'SELECT email, SUM(quant_flexoes) AS total_flexoes FROM flexoes GROUP BY email ORDER BY total_flexoes DESC';
        const [ranking] = await pool.promise().query(query);
        console.log(ranking)
        res.status(200).send(ranking)
    } catch (error) {
        console.error('Erro ao buscar dados de flexões:', error);
        res.status(500).send('Erro ao buscar dados de flexões');
    }
});

app.get('/about-us', (req, res) => {
    res.render('about-us.ejs', { title: 'Sobre Nós' });
});

const port = process.env.PORT || 4000;

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
