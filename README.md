# MovieShop

A full-stack web application for browsing and purchasing movie tickets, built with Node.js, Express, and EJS templating.

## Overview

MovieShop is a server-rendered web app where users can answer a quiz, purchase movies through a Node.js/Express backend, with data persisted in a local SQLite database.

## Features

- **User accounts:** registration/login with password handling (`generate_pass.js`)
- **Purchases:** ticket/purchase data stored in a SQLite database (`shop.db`)
- **Quiz/interactive content:** question data served from `questions.json`
- **Server-rendered views:** EJS templates for the front end
- **Styling:** custom CSS

## Tech Stack

- **Backend:** Node.js, Express
- **Templating:** EJS
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript

## Project Structure

```
MovieShop/
├── views/        # EJS templates
├── public/css/   # Stylesheets
├── app.js        # Application entry point
├── shop.db       # SQLite database (purchases)
├── questions.json       # Quiz/question data
├── generate_pass.js  # Password generation script
└── users.json     # User data
```

## How to Run

```bash
node app.js
```


## What I Learned

This project helped me practice building a full server-rendered web application end-to-end: routing, templating, basic authentication, and persisting data with SQLite.

