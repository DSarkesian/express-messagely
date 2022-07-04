"use strict";
const db = require("../db");
const BCRYPT_WORK_FACTOR = require("../config");
const Message = require("./message");
const bcrypt = require("bcrypt");

/** User of the site. */

class User {

  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone)
        VALUES
        ($1,$2,$3,$4,$5)
        RETURNING username`,
      [username, hashedPassword, first_name, last_name, phone]);
    return new User(result.rows[0])
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {

    const result = await db.query(
      `SELECT password
      FROM users
      WHERE username = $1`
      [username]);
    const user = result.rows[0]

    return (await bcrypt.compare(password, user.password) === true)

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username,
        first_name,
        last_name
      FROM users
      ORDER BY last_name, first_name`
    );
    return results.rows.map(u => new User(u));
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username, 
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at
      FROM users
      WHERE username = $1`, 
      [username]
    );

    return new User(result.rows[0]);
  }


  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT messages.id,
        messages.to_user,
        messages.body,
        messages.sent_at,
        messages.read_at
      FROM messages
        JOIN users ON messages.from_username = $1`,
        [username]
    );
    const messages = results.rows.map(async id => await Message.get(id));
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT messages.id,
        messages.from_user,
        messages.body,
        messages.sent_at,
        messages.read_at
      FROM messages
        JOIN users ON messages.to_username = $1`,
        [username]
    );
    const messages = results.rows.map(async id => await Message.get(id));
    return messages;
  }
}


module.exports = User;
