const Joi = require('joi');

// Layer 1a: strict input validation (allow-list). Anything not matching is rejected.
const registerSchema = Joi.object({
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).max(72).required(),
  // the "sensitive" field, e.g. a phone or ID number
  sensitiveInfo: Joi.string().pattern(/^[A-Za-z0-9 -]{4,32}$/).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(1).max(72).required(),
});

module.exports = { registerSchema, loginSchema };
