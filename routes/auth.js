"use strict";

const { SECRET_KEY } = require("../config");
const { UnauthorizedError } = require("../expressError");
const User = require("../models/user");
const jwt = require("jsonwebtoken");

const Router = require("express").Router;
const router = new Router();

/** POST /login: {username, password} => {token} */
router.post("/login", async function (req, res) {
    const { username, password } = req.body;
    const auth = await User.authenticate(username, password);
    if (auth === true) {
        User.updateLoginTimestamp(username);
        const token = jwt.sign({ username }, SECRET_KEY);

        console.log("Logged in!")
        return res.json({ token });
    }

    throw new UnauthorizedError("Invalid user/password");
});




/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */
router.post("/register", async function (req, res) {
    const username = User.register(req.body);
    const token = jwt.sign({ username }, SECRET_KEY);

    console.log("Registered!")
    return res.json({ token });

});

module.exports = router;
