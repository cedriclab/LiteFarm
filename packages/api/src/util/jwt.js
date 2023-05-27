import jwt from 'jsonwebtoken';

import { client } from './redis';

import { randomBytes } from 'crypto';

const ACCESS_TOKEN_EXPIRES_IN = '7d';
const RESET_PASSWORD_TOKEN_EXPIRES_IN = '1d';
const SCHEDULER_TOKEN_EXPIRES_IN = '1d';

const DEFAULT_RANDOM_TOKEN_LENGTH = 32;

const tokenType = {
  access: process.env.JWT_SECRET,
  invite: process.env.JWT_INVITE_SECRET,
  passwordReset: process.env.JWT_RESET_SECRET,
  farm: process.env.JWT_FARM_SECRET,
  scheduler: process.env.JWT_SCHEDULER_SECRET,
};
const expireTime = {
  access: ACCESS_TOKEN_EXPIRES_IN,
  invite: ACCESS_TOKEN_EXPIRES_IN,
  passwordReset: RESET_PASSWORD_TOKEN_EXPIRES_IN,
  farm: ACCESS_TOKEN_EXPIRES_IN,
  scheduler: SCHEDULER_TOKEN_EXPIRES_IN,
};

const SINGLE_USE_TOKEN_LENGTH = 256;
const REFRESH_TOKEN_LENGTH = 128;

const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION || 7 * 24 * 60 * 60; // Defaults to 7 days - time is in SECONDS, not MS

const SingleUseTokenType = {
  REFRESH: 'REFRESH',
  EMAIL: 'EMAIL',
};

function createToken(type, payload) {
  return jwt.sign(payload, tokenType[type], {
    expiresIn: expireTime[type],
    algorithm: 'HS256',
  });
}

const getCookieOptions = (cookie, opts = {}) => {
  return {
    //signed: true,
    httpOnly: true,
    //domain: 'localhost:3001', // TODO - make based on config
    sameSite: 'Lax',
    //path: '/*',
    ...opts,
  };
};

/**
 * @function createRandomToken
 * @description Creates a cryptographically safe random string of a given length
 * @async
 * @param {Number} length - the length of the token
 * @returns {String}
 */
const createRandomToken = async (length = DEFAULT_RANDOM_TOKEN_LENGTH) => {
  return new Promise((resolve, reject) => {
    randomBytes(length, (err, buffer) => {
      if (err) {
        return reject(err);
      }

      const token = buffer.toString('hex');

      return resolve(token);
    });
  });
};

/**
 * @function emitSingleUseToken
 * @description Emits a single-use token and stores it in Redis
 * @param {SingleUseTokenType} type
 * @param {Object} info - the payload to go along with the key
 * @param {Object} options - options; generally the length and the expiration
 */
const emitSingleUseToken = async (type, info, options) => {
  const tokenLength = (options && options.length) || SINGLE_USE_TOKEN_LENGTH;

  // create the random token
  const token = await createRandomToken(tokenLength);

  // Use the token and the type to create a redis key
  const key = `token.${type.toLowerCase()}.${token}`;

  // Here, we set the expiration for the token
  const tokenExpiration = (options && options.expiration) || REFRESH_TOKEN_EXPIRATION;

  // Store the token in redis, with expiration
  await client.set(key, JSON.stringify(info), 'EX', tokenExpiration);

  return token;
};

// Just a shorthand for emitSingleUseToken with REFRESH set as type and REFRESH_TOKEN_LENGTH as the length
const emitRefreshToken = async (info) => {
  return emitRefreshToken(SingleUseTokenType.REFRESH, info, { length: REFRESH_TOKEN_LENGTH });
};

const validateSingleUseToken = async (type, token) => {
  // Use the token and the type to create a redis key
  const key = `token.${type.toLowerCase()}.${token}`;

  const payload = await client.get(key);

  if (payload) {
    try {
      return JSON.parse(payload);
    } catch (e) {
      console.error(
        `An entry exists for the key "${key}", but it cannot be processed because ->`,
        e,
      );
      return null;
    }
  }

  return null;
};

export {
  createToken,
  expireTime,
  tokenType,
  SINGLE_USE_TOKEN_LENGTH,
  REFRESH_TOKEN_LENGTH,
  SingleUseTokenType,
  emitRefreshToken,
  emitSingleUseToken,
  validateSingleUseToken,
  getCookieOptions,
};
