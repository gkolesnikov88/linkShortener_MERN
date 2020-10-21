const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator')
const User = require('../models/User');
const router = new Router();

// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Wrong email').isEmail(),
    check('password', 'Minimum password length is 6 symbols')
      .isLength({min: 6}),
  ],
  async (req, resp) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return resp.status(400).json({
        errors: errors.array(),
        message: 'Incorrect registration data',
      });
    }

    const {email, password} = req.body;

    const candidate = await User.findOne({email: email});
    if (candidate) {
      return resp.status(400).json({message: 'User is defined'});
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({email, password: hashedPassword});
    await user.save();
    resp.status(201).json({ message: 'User created'});

  } catch (e) {
    resp.status(500).json({ message: 'Something go wrong, please try later'});
  }
});

// /api/auth/login
router.post('/login',
  [
    check('email', 'Enter correct email').normalizeEmail().isEmail(),
    check('password', 'Enter password').exists(),
  ],
  async (req, resp) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return resp.status(400).json({
          errors: errors.array(),
          message: 'Incorrect log in data',
        });
      }

      const {email, password} = req.body;

      const user = await User.findOne({email});

      if (!user) {
        return resp.status(400).json({message: 'User is not defined'});
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return resp.status(400).json({message: 'Password incorrect'});
      }

      const token = jwt.sign(
        { userId: user.id,},
        config.get('jwtSecretKey'),
        { expiresIn: '1h'}
        );

      resp.json({token, userId: user.id});

    } catch (e) {
      resp.status(500).json({ message: 'Something go wrong, please try later'});
    }
});

module.exports = router;
