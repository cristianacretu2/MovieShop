const bcrypt = require('bcrypt');
const saltRounds = 10;
const parolaMea = 'parola'; // de schimbat pt verificare altele

bcrypt.hash(parolaMea, saltRounds, (err, hash) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log("Copiaza acest hash in utilizatori.json:");
    console.log(hash);
});

