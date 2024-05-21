const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require("jsonwebtoken");

const getAll = catchError(async (_, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const encryptPassword = await bcrypt.hash(password, 10);
  const code = require("crypto").randomBytes(32).toString("hex");

  await sendEmail({
    to: email,
    subject: "Work node verify user",
    html: `
      <a href=${frontBaseUrl}/${code}>${frontBaseUrl}/${code}</a>
    `,
  });

  const result = await User.create({
    email,
    password: encryptPassword,
    firstName,
    lastName,
    country,
    image,
  });

  const userId = result.id;
  await EmailCode.create({
    code,
    userId,
  });

  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { email, firstName, lastName, country, image } = req.body;
  const result = await User.update(
    {
      email,
      firstName,
      lastName,
      country,
      image,
    },
    {
      where: { id },
      returning: true,
    }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyUserCode = catchError(async (req, res) => {
  const { code } = req.params;
  const validCode = await EmailCode.findOne({ where: { code } });
  if (!validCode)
    return res.status(401).json({ message: "Código de usuario invalido" });

  const user = await User.findByPk(validCode.userId);
  user.isVerified = true;
  await user.save();

  await validCode.destroy();

  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  if (!user.isVerified)
    return res.status(401).json({ message: "User no verified" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });

  return res.json({ user, token });
});

const loggedUser = catchError(async (req, res) => {
  return res.json(req.user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyUserCode,
  login,
  loggedUser,
};
