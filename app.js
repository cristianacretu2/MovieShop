
const session = require('express-session'); // pt tema 3 - lab 11

const sqlite3 = require('sqlite3').verbose(); // pt tema 1 - lab 12

const bcrypt = require('bcrypt'); // lab 13 - tema 1 c

const csrf = require('csurf'); // lab 13 - tema 2 -> protectie impotriva csrf

const { body, validationResult } = require('express-validator'); // lab 13 - tema 1 b

const rateLimit = require('express-rate-limit'); // pentru lab 13 - tema 3 

const blockedIPs = new Set();

// stocam nr de erori per fiecare ip 
const errorStats = new Map();

// cream db
const db = new sqlite3.Database('./cumparaturi.db', (err) => {
    if (err) {
        console.log("eroare la deschiderea bazei de date", err.message);
    } 
    else {
        console.log("conectat la baza de date sqlite");
    }
});

const express = require('express');

const expressLayouts = require('express-ejs-layouts');

const bodyParser = require('body-parser')

const app = express();
//app.set('trust proxy', 1); // pt loginlimiter ? 

// limitator pt login
// lab 13 - tema 3
const loginLimiter = rateLimit({
    windowMs: 3 * 60 * 1000, // interval de 3 minute
    max: 2, // maxim 5 incercari nereusite
    message: 'Prea multe încercări de autentificare. Vă rugăm să încercați din nou peste 15 minute.',
    standardHeaders: true, 
    legacyHeaders: false,
    skipSuccessfulRequests: true, // doar cererile esuate sunt contorizate

    handler: (req, res, next, options) => {
        res.status(options.statusCode).send(`
            <script>
                alert("Prea multe încercări! Te rugăm să aștepți 15 minute.");
                window.location.href = "/autentificare"; 
            </script>
        `);
    }

});

// configurare sesiune securizata - lab 13 - tema 2
app.use(session({
    secret: 'secret_key_2',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // previne acces la cookie prin js (xss)
        secure: false, 
        maxAge: 1000 * 60 * 60 // 1 ora
    }
}));

const port = 6789;

const csrfProtection = csrf(); // activare protectie csrf

const cookieParser = require('cookie-parser'); // pt lab 11 - tema 2


// directorul 'views' va conține fișierele .ejs (html + js executat la server)
app.set('view engine', 'ejs');


// suport pentru layout-uri - implicit fișierul care reprezintă template-ul site-ului
// este views/layout.ejs
app.use(expressLayouts);


// directorul 'public' va conține toate resursele accesibile direct de către client
// (e.g., fișiere css, javascript, imagini)
app.use(express.static('public'));


// corpul mesajului poate fi interpretat ca json; datele de la formular se găsesc în
// format json în req.body
app.use(bodyParser.json());


// utilizarea unui algoritm de deep parsing care suportă obiecte în obiecte
// middleware pt a procesa datele din formular - lab 11
app.use(bodyParser.urlencoded({ extended: true }));

app.use( cookieParser() ); // pt cookie, lab 11 - tema 2 


// la accesarea din browser adresei http://localhost:6789/ se va returna textul 'Hello
// World'

const fs = require('fs').promises;

// facem un limitator general 
const globalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minut
    max: 100, // Maxim 100 cereri pe minut per IP
    message: "Acces blocat temporar din cauza activității suspecte (DoS Protection).",
    
});

app.use(globalLimiter);

app.use((req, res, next) => {
    res.locals.utilizatorSesiune = req.session.utilizator || null;
    res.locals.numeComplet = req.session.numeComplet || null;
    next();
});


// proprietățile obiectului Request - req - https://expressjs.com/en/api.html#req
// proprietățile obiectului Response - res - https://expressjs.com/en/api.html#res

// tema 2 - lab 12
// ne asiguram ca fiecare utilizator are cos 
app.use((req, res, next) => {
    if (!req.session.cos) {
        req.session.cos = [];
    }

    // ca sa fie variabila accesibila in index.ejs
    res.locals.utilizator = req.session.utilizator || null;
    res.locals.session = req.session || null;
    next();
});


// lab 13 - tema 3 
// middleware pt monitorizare eroare 404 (DoS)
app.use((req, res, next) => {
    const ip = req.ip;
    
    res.on('finish', () => {
        if (res.statusCode === 404) {
            const currentErrors = errorStats.get(ip) || 0;
            errorStats.set(ip, currentErrors + 1);

            if (currentErrors + 1 > 5) { // Prag de 10 erori 404
                console.log(`IP blocat temporar pentru scanare: ${ip}`);
                // Aici am putea adăuga IP-ul într-o listă de block
            }
        }
    });
    next();
});

// modificam ruta pt team 2 - lab 11 
// modificam ruta pt tema 2 - lab 12
// modificam ruta pt tema 1 - lab 13
app.get('/', (req, res) =>  {

    const numeAfisat = (req.session.prenume && req.session.nume) 
                       ? (req.session.prenume + " " + req.session.nume) 
                       : null;

    // luam filmele din baza de date 
    db.all("SELECT * FROM produse", [], (err, rows) => {
        if (err) {
            console.error(err.message);
            return res.render('index', { 
                utilizator: numeAfisat, 
                produse: rows 
            });
        }
        // trimitem rezultatele catre index
        res.render('index', { 
            utilizator: numeAfisat, 
            produse: rows 
        });
    });

}); // randeaza index.ejs 

// ruta pt inregistrare
app.get('/inregistrare', (req, res) => {
    res.render('inregistrare', { eroare: null });
});

// ruta pt creare cont
app.post('/creare-cont', [
    // validare si sanitizare
    body('utilizator').trim().escape().isLength({ min: 3 }).withMessage('Minim 3 caractere la utilizator'),
    body('nume').trim().escape().notEmpty().withMessage('Numele este obligatoriu'),
    body('prenume').trim().escape().notEmpty().withMessage('Prenumele este obligatoriu'),
    body('parola').isLength({ min: 5 }).withMessage('Parola trebuie să aibă minim 5 caractere')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('inregistrare', { eroare: errors.array()[0].msg });
    }

    const { utilizator, nume, prenume, parola } = req.body;

    try {
        const data = await fs.readFile('./utilizatori.json', 'utf8');
        let listaUtilizatori = JSON.parse(data);

        if (listaUtilizatori.find(u => u.utilizator === utilizator)) {
            return res.render('inregistrare', { eroare: 'Acest utilizator există deja.' });
        }

        // [Punctul C] Hashing cu Bcrypt
        const saltRounds = 10;
        const hash = await bcrypt.hash(parola, saltRounds);

        const noulUtilizator = { utilizator, nume, prenume, parola: hash };
        listaUtilizatori.push(noulUtilizator);

        await fs.writeFile('./utilizatori.json', JSON.stringify(listaUtilizatori, null, 2));
        res.redirect('/autentificare');
    } catch (err) {
        res.status(500).send("Eroare la server.");
    }
});

// ruta pt afisare formular de autentificare. modificam rutele pt tema 2
app.get('/autentificare', (req, res) => {

    const mesaj = req.cookies.mesajEroare || null;

    res.clearCookie('mesajEroare');

    res.render('autentificare', { eroare: mesaj });
});

// la accesarea din browser adresei http://localhost:6789/chestionar se va apela funcția
// specificată
// afisare chestionar
app.get('/chestionar', async (req, res) => {
    try {
        // citire asincrona din fisier (tema 3 - lab 10)
        const data = await fs.readFile('./intrebari.json', 'utf8');
        const listaIntrebari = JSON.parse(data);
        res.render('chestionar', { intrebari: listaIntrebari });
    } catch (err) {
        res.status(500).send("Eroare la citirea întrebărilor.");
    }
});

app.use((req, res, next) => {
    const ip = req.ip;
    
    // Verificăm dacă IP-ul este deja blocat
    if (blockedIPs.has(ip)) {
        return res.status(403).send('<h1>Acces Interzis</h1><p>IP-ul tău a fost blocat pentru activitate suspectă.</p>');
    }

    res.on('finish', () => {
        if (res.statusCode === 404) {
            const currentErrors = errorStats.get(ip) || 0;
            errorStats.set(ip, currentErrors + 1);

            if (currentErrors + 1 > 5) { 
                console.log(`IP blocat: ${ip}`);
                blockedIPs.add(ip); // adaugam ip la blocati
                
                // scoatem ip ul din lista dupa o ora 
                setTimeout(() => blockedIPs.delete(ip), 3600000);
            }
        }
    });
    next();
}); 

// procesare rezultat ( tema 2 - lab 10)
// actualizare tema 1 b - lab 13
app.post('/rezultat-chestionar', async (req, res) => {
    try {
        const data = await fs.readFile('./intrebari.json', 'utf8');
        const listaIntrebari = JSON.parse(data);
        let scor = 0;

        // logica de verificare (tema 2.b)
        listaIntrebari.forEach((intrebare, index) => {
            const raspunsUtilizator = req.body[`raspuns-${index}`];
            // validare manuala 
            if (raspunsUtilizator !== undefined) {
                if (parseInt(raspunsUtilizator) === intrebare.corect) {
                    scor++;
                }
            }
            
        });

        // randarea rezultatului folosind acelasi layout (tema 2.c)
        res.render('rezultat-chestionar', { 
            scor: scor, 
            total: listaIntrebari.length 
        });
    } catch (err) {
        res.status(500).send("Eroare la procesarea rezultatelor.");
    }
});

// logica de verificare pt autentificare 
// actualizare lab 13 - tema 1 b si c 
app.post('/verificare-autentificare', loginLimiter, [
    body('utilizator').trim().escape(),
    body('parola').trim().escape()
], async (req, res) => {
    const { utilizator, parola } = req.body;
    try {
        const data = await fs.readFile('./utilizatori.json', 'utf8');
        const listaUtilizatori = JSON.parse(data);
        const userFound = listaUtilizatori.find(u => u.utilizator === utilizator);

        // [Punctul C] Verificare hash
        if (userFound && await bcrypt.compare(parola, userFound.parola)) {
            req.session.utilizator = userFound.utilizator;
            req.session.prenume = userFound.prenume;
            req.session.nume = userFound.nume;
            req.session.rol = userFound.rol; // salvam rolul - lab 13 - tema 2
            res.redirect('/');
        } else {
            res.cookie('mesajEroare', 'Utilizator sau parolă incorectă!');
            res.redirect('/autentificare');
        }
    } catch (err) {
        res.status(500).send("Eroare.");
    }
});

// ruta pt deconectare 
app.get('/deconectare', (req, res) => {
    req.session.destroy();
    res.clearCookie('utilizator');
    res.redirect('/');
});

// rute pt lab 12 - Baza de date 
// creare tabela de produse 
app.post('/creare-bd', (req, res) => {
    const sql = `CREATE TABLE IF NOT EXISTS produse (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nume VARCHAR(100) NOT NULL,
        pret DECIMAL(10, 2) NOT NULL,
        descriere TEXT
    )`;
    
    db.run(sql, (err) => {
        if (err) {
            return res.status(500).send("Eroare: " + err.message);
        }

        console.log("Tabela produse a fost creată în fișier.");
        res.redirect('/');
    });
 
});

// inserare filme in tabela 
app.post('/inserare-bd', (req, res) => {
    const filme = [
        ['Inception', 25.50, 'Un hoț care fură secrete prin tehnologia de partajare a viselor.'],
        ['The Dark Knight', 30.00, 'Batman se confruntă cu Joker în Gotham City.'],
        ['Interstellar', 28.00, 'O echipă de exploratori călătoresc printr-o gaură de vierme pentru a salva omenirea.'],
        ['Pulp Fiction', 22.00, 'Viețile a doi asasini plătiți, un boxer și un gangster se intersectează.'],
        ['The Matrix', 24.50, 'Un hacker descoperă natura adevărată a realității sale.']
    ];

    // tema 1 lab 13 - folosim ? pt a preveni sql injection
    const sql = "INSERT INTO produse (nume, pret, descriere) VALUES (?, ?, ?)";
    
    // inseram filmele 
    filme.forEach((film) => {
        db.run(sql, film, (err) => {
            if (err) {
                console.error("Eroare la inserare film:", err.message);
            }
        });
    });

    console.log("Comenzile de inserare au fost trimise.");
    res.redirect('/');
    
});

app.listen(port, () => console.log(`Serverul rulează la adresa http://localhost:${port}/`));

// la inchiderea serverului 
process.on('SIGINT', () => {
console.log('Primire semnal oprire (SIGINT)...');

    const sql = "DROP TABLE IF EXISTS produse";
    
    // icnercam sa stergem tables
    db.run(sql, (err) => {
        if (err) {
            console.error("Eroare la ștergerea tabelei înainte de închidere:", err.message);
        } else {
            console.log("Tabela 'produse' a fost ștearsă.");
        }

        // dupa ce s a terminat db.run (cu succes sau eroare), inchidem conexiunea
        db.close((errClose) => {
            if (errClose) {
                console.error("Eroare la închiderea bazei de date:", errClose.message);
            } else {
                console.log('Conexiunea SQLite a fost închisă.');
            }
            
            // 3. Abia acum închidem procesul de tot
            process.exit(0);
        });
    });
});

// ruta pentru adaugare cos -> tema 2 - lab 12
// actualizare lab 13 - tema 1 -> securizare cos cumparaturi
app.post('/adaugare-cos', [
        body('id').isInt().toInt() // ne asiguram ca id ul este nr intreg
    ], (req, res) => {
        const idProdus = req.body.id; // luam id ul trimis prin inputul hidden din index.ejs

        // verificam ca sesiunea sa existe 
        if (req.session.cos) {
            req.session.cos.push(idProdus); // adaugam id ul produsului
            console.log("produs adaugat in cos. cosul actual: ", req.session.cos);
        } else {
            // daca sesiunea s a pierdut
            req.session.cos = [idProdus];
        }

        // redirectionam utilizatorul catre pagina principala 
        res.redirect('/');
});

// ruta pt vizualizare-cos
app.get('/vizualizare-cos', (req, res) => {
    const cos = req.session.cos || [];
    if (cos.length == 0) return res.render('vizualizare-cos', { produse: [], total: 0 });

    const placeholders = cos.map(() => '?').join(',');
    const sql = `SELECT * FROM produse WHERE id IN (${placeholders})`;

    // transmitem array ul cos ca parametru pentru a fi injectat in locul semnelor de intrebare
    db.all(sql, cos, (err, rows) => {
        if (err) return res.status(500).send("Eroare la server");
        let total = 0;
        rows.forEach(produs => { total += produs.pret; });
        res.render('vizualizare-cos', { produse: rows, total: total });
    });
});

// LAB 13 - ROLURI 
// middle ware pt verificare rol de admin 
function verificaAdmin(req, res, next) {
    if (req.session.utilizator && req.session.rol === 'ADMIN') {
        next();
    } else {
        res.status(403).send('403 Forbidden: Acces rezervat administratorilor.');
    }
}

// afisare pagina admin

// csrfProtection genereaza un token pe care il trimitem in pagina
app.get('/admin', verificaAdmin, csrfProtection, (req, res) => {
    res.render('admin', { csrfToken: req.csrfToken() });
});

// adaugare produs nou - rol admin 
app.post('/admin/adaugare-produs', verificaAdmin, csrfProtection, (req, res) => {
    const { nume, pret, descriere } = req.body;
    const sql = "INSERT INTO produse (nume, pret, descriere) VALUES (?, ?, ?)";
    
    db.run(sql, [nume, pret, descriere], (err) => {
        if (err) return res.status(500).send("Eroare la inserare.");
        res.redirect('/');
    });
});


