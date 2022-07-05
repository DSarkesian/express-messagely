"use strict";
const db = require("../db");
const BCRYPT_WORK_FACTOR = require("../config");
const Message = require("./message");
const bcrypt = require("bcrypt");
const { UnauthorizedError } = require("../expressError");

/** User of the site. */

class User {


  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, Number(BCRYPT_WORK_FACTOR))
    const result = await db.query(
      `INSERT INTO users (
        username,
        password,
        first_name,
        last_name,
        phone,
        join_at)
        VALUES
        ($1,$2,$3,$4,$5, current_timestamp)
        RETURNING username,password,first_name,last_name,phone`,
      [username, hashedPassword, first_name, last_name, phone]);

    return result.rows[0]
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {

    const result = await db.query(
      `SELECT password, username
      FROM users
      WHERE username = $1`,
      [username]);
    const user = result.rows[0];
    if(user){
      return await bcrypt.compare(password, user.password) === true;
    }
    throw new UnauthorizedError();

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
      WHERE username = $1`, [username]);
    const user = result.rows[0];
    if(!user){
      throw new UnauthorizedError();
      }

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
    return results.rows;
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
    const user = result.rows[0];
    if(!user){
      throw new UnauthorizedError();
      }

    return user
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
        messages.to_username AS to_user,
        messages.body,
        messages.sent_at,
        messages.read_at,
        users.username,
        users.first_name,
        users.last_name,
        users.phone
      FROM messages
        JOIN users ON messages.to_username = users.username
      WHERE messages.from_username = $1`, [username]
    );

    const messages = results.rows.map(
      row => row = {
        id: row.id,
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at,
        to_user: {
          username: row.username,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone
          }
        });

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
        messages.to_username AS to_user,
        messages.body,
        messages.sent_at,
        messages.read_at,
        users.username,
        users.first_name,
        users.last_name,
        users.phone
      FROM messages
        JOIN users ON messages.from_username = users.username
      WHERE messages.to_username = $1`, [username]
    );

    const messages = results.rows.map(
      row => row = {
        id: row.id,
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at,
        from_user: {
          username: row.username,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone
          }
        });

    return messages
  }
}


module.exports = User;
