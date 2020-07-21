const moment = require("moment");
const pad = require("pad-component");
const crypto = require("crypto");

/*
    An RFC6238 compliant package for generating a TOTP, Time-based one-time password.
    RFC6238 Spec: https://tools.ietf.org/html/rfc6238
*/

/**
 * Return a buffer (bytes) of given argument.
 * If given argument is number, return Buffer with size of 8 bytes padded with 0 from left
 * If given argument is string, return Buffer with full size of the strings
 *
 * @param {(string|number)} arg
 * @return {Buffer} buffer object
 */
function toBuffer(arg) {
  let buffer;
  if (typeof arg === "string") buffer = Buffer.from(arg);
  else {
    buffer = Buffer.alloc(8);
    buffer.writeUInt32BE(arg, 4);
  }
  return buffer;
}

/**
 *
 * This function takes a hash from generateTOTP function and truncates it
 *
 * @param {string} hash Hex strings that will be truncated from offset byte to offset + 4 byte
 * @param {number} passwordLength Desired TOTP lengtb
 * @returns {string} Numerical string in base 10 of the truncated hex strings
 */
const truncate = (hash, passwordLength) => {
  const offset = parseInt(hash.charAt(hash.length - 1), 16);

  let res = parseInt(hash.substr(offset * 2, 8), 16);

  // Get only last 31 bits of result
  res = res & 0x7fffffff;

  return pad(String(res), passwordLength, "0");
};

const DEFAULT_HASH_ALGORITHM = "sha1"; //default hasing algorithm
const DEFAULT_T0 = 0; //default time zero
const DEFAULT_TS_X = 30; //default timestep
const DEFAULT_PW_LENGTH = 10; //default generated password length

/**
 * TOTP algorithm implementation
 *
 * @param {string} secret_key Key for hashing
 * @param {number} T T is Unix time, if not given default to current Unix time
 * @param {number} T0  Unix time to start counting time steps,
 * @param {number} TS_X  time step in seconds
 * @param {HashAlgorithm} [algorithm=sha1] HMAC Algorithm, either 'sha1', or 'sha256' or 'sha512'. Default is sha1
 * @param {number} passwordLength Desired TOTP length
 */
const generateTOTP = ({
  secret_key, // key for hash algorithm
  T, // T is epoch time (Unix time), if not given compute current Unix time
  T0 = DEFAULT_T0, // the Unix time to start counting time steps
  TS_X = DEFAULT_TS_X, // TOTP's Timestep X
  algorithm = DEFAULT_HASH_ALGORITHM,
  passwordLength = DEFAULT_PW_LENGTH,
}) => {
  //calculate unix time, if not provided
  const counter = Math.floor(((!T ? moment().unix() : T) - T0) / TS_X);
  const skBytes = toBuffer(secret_key);
  const counterBytes = toBuffer(counter);
  const hash = crypto
    .createHmac(algorithm, skBytes)
    .update(counterBytes)
    .digest("hex");
  return truncate(hash, passwordLength);
};

module.exports = generateTOTP;
