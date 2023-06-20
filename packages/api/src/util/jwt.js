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
  passwordReset: process.env.JWT_RESET_SECRET, // may not be needed anymore
  farm: process.env.JWT_FARM_SECRET,
  scheduler: process.env.JWT_SCHEDULER_SECRET,
};
const expireTime = {
  access: ACCESS_TOKEN_EXPIRES_IN,
  invite: ACCESS_TOKEN_EXPIRES_IN,
  passwordReset: RESET_PASSWORD_TOKEN_EXPIRES_IN, // may not be needed anymore
  farm: ACCESS_TOKEN_EXPIRES_IN,
  scheduler: SCHEDULER_TOKEN_EXPIRES_IN,
};

const SINGLE_USE_TOKEN_LENGTH = 128;
const REFRESH_TOKEN_LENGTH = 128;

const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION || 7 * 24 * 60 * 60; // Defaults to 7 days - time is in SECONDS, not MS

const SINGLE_USE_TOKEN_SECRET = process.env.SINGLE_USE_TOKEN_SECRET;

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
 * @description Emits a single-use token, stores it in Redis, and returns a SIGNED version
 * @note We use a 2-step approach here: first, we create a random token, which we will store in Redis along with a payload in JSON format.  This Key/Value pair is set to expire after the provided validity period.  Then, we sign this token in the format of a JWT with the same expiration time, and we send that signed token out.
 * @note Why not just use the random token OR the signed token?  The random token alone can be the target of a brute-force attack.  The signed token alone is harder to invalidate after use (because the tokens are single-use).  With the 2 steps, we have both security against brute-force attacks AND easy invalidation after use.
 * @param {SingleUseTokenType} type
 * @param {Object} info - the payload to go along with the key
 * @param {Object} options - options; generally the length and the expiration
 * @returns {String} - a signed token, in the format of a JWT, which's payload contains { token, userId } which can then be used to retrieve a whole payload from redis
 */
const emitSingleUseToken = async (type, info, options) => {
  const tokenLength = (options && options.length) || SINGLE_USE_TOKEN_LENGTH;

  // create the random token
  const token = await createRandomToken(tokenLength);

  const tokenPayload = { type, token, userId: info.user_id };

  // Here, we set the expiration for the token
  const tokenExpiration = (options && options.expiration) || REFRESH_TOKEN_EXPIRATION;

  const signedToken = await jwt.sign(tokenPayload, SINGLE_USE_TOKEN_SECRET, {
    expiresIn: `${tokenExpiration}s`,
    algorithm: 'HS256',
  });

  // Use the token and the type to create a redis key
  const key = `token.${type.toLowerCase()}.${token}`;

  // Store the token in redis, with expiration
  await client.set(key, JSON.stringify(info), 'EX', tokenExpiration);

  return signedToken;
};

// Just a shorthand for emitSingleUseToken with REFRESH set as type and REFRESH_TOKEN_LENGTH as the length
const emitRefreshToken = async (info) => {
  return emitSingleUseToken(SingleUseTokenType.REFRESH, info, { length: REFRESH_TOKEN_LENGTH });
};

/**
 * @function validateSingleUseToken
 * @description This function is the inverse of emitSingleUseToken, except that, if provided with the optional argument invalidateToken = true, it will have the side-effect of invalidating the provided token
 * @note IN NORMAL CASES, invalidateToken *should* be true because it is the mechanism whereby we can invalidate SINGLE-USE tokens after they have been used.
 * @param {String} signedToken
 * @param {Boolean} invalidateToken
 * @returns {Object|Null}
 */
const validateSingleUseToken = async (signedToken, invalidateToken = true) => {
  const parsedPayload = await jwt.verify(signedToken, SINGLE_USE_TOKEN_SECRET).catch((error) => {
    console.error(
      `Could not decrypt signed single-use token because [likely it has expired]->`,
      error,
    );
    return null;
  });

  if (!parsedPayload) {
    return null;
  }

  const { token, type } = parsedPayload;

  // Use the token and the type to create a redis key
  const key = `token.${type.toLowerCase()}.${token}`;

  const payload = await client.get(key);

  if (payload) {
    // By default, we invalidate the token once it has been validated because they are single-use
    if (invalidateToken) {
      await client.del(key);
    } else {
      // Just a pesky warning
      console.warn(
        `The "validateSingleUseToken" with the invalidateToken argument set to false.  Be careful!  This is how we make sure single-use tokens are, well, single-use.`,
      );
    }

    try {
      const parsedPayload = JSON.parse(payload);

      return { type, payload: parsedPayload };
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
