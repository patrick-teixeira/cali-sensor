const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const pool = require('./database');

function initialize(passport) {
    const authenticateUser = (email, password, done) => {
        pool.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
            if (err) {
                return done(err);
            }
            if (results.length === 0) {
                return done(null, false, { message: 'No user with that email' });
            }

            const user = results[0];
            try {
                const match = await bcrypt.compare(password, user.senha);
                if (match) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Password incorrect' });
                }
            } catch (error) {
                return done(error);
            }
        });
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));

    passport.serializeUser((user, done) => {
        done(null, user.idusuarios);
    });

    passport.deserializeUser((id, done) => {
        pool.query('SELECT * FROM usuarios WHERE idusuarios = ?', [id], (err, results) => {
            if (err) {
                return done(err);
            }
            return done(null, results[0]);
        });
    });
}

module.exports = initialize;
