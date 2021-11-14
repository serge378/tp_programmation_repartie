const bcrypt = require("bcryptjs");
const { UserInputError, AuthenticationError } = require("apollo-server");
const jwt = require("jsonwebtoken");
const { Op } = require("sequelize");

const { Message, User } = require("../../models");

module.exports = {
  Query: {
    getUsers: async (_, __, { user }) => {
      try {
        if (!user) throw new AuthenticationError("Non authentifié");

        let users = await User.findAll({
          attributes: ["username", "imageUrl", "createdAt"],
          where: { username: { [Op.ne]: user.username } },
        });

        const allUserMessages = await Message.findAll({
          where: {
            [Op.or]: [{ from: user.username }, { to: user.username }],
          },
          order: [["createdAt", "DESC"]],
        });

        users = users.map((otherUser) => {
          const latestMessage = allUserMessages.find(
            (m) => m.from === otherUser.username || m.to === otherUser.username
          );
          otherUser.latestMessage = latestMessage;
          return otherUser;
        });

        return users;
      } catch (err) {
        console.log(err);
        throw err;
      }
    },
    login: async (_, args) => {
      const { username, password } = args;
      let errors = {};

      try {
        if (username.trim() === "")
          errors.username = "Le nom d'utilisateur ne doit pas être vide";
        if (password === "")
          errors.password = "Le mot de passe ne doit pas être vide";

        if (Object.keys(errors).length > 0) {
          throw new UserInputError("Mauvaise saisie", { errors });
        }

        const user = await User.findOne({
          where: { username },
        });

        if (!user) {
          errors.username = "Cet utilisateur n'existe pas";
          throw new UserInputError("Cet utilisateur n'existe pas", { errors });
        }

        const correctPassword = await bcrypt.compare(password, user.password);

        if (!correctPassword) {
          errors.password = "Mot de passe incorrecte";
          throw new UserInputError("Mot de passe incorrecte", { errors });
        }

        const token = jwt.sign({ username }, process.env.JWT_SECRET, {
          expiresIn: 60 * 60,
        });

        return {
          ...user.toJSON(),
          token,
        };
      } catch (err) {
        console.log(err);
        throw err;
      }
    },
  },
  Mutation: {
    register: async (_, args) => {
      let { username, email, password, confirmPassword } = args;
      let errors = {};

      try {
        // Validate input data
        if (email.trim() === "") errors.email = "L'email de doit pas être vide";
        if (username.trim() === "")
          errors.username = "Le nom d'utilisateur ne doit pas être vide";
        if (password.trim() === "")
          errors.password = "Le mot de passe ne doit pas être vide";
        if (confirmPassword.trim() === "")
          errors.confirmPassword = "Le mode de passe ne doit pas être vide";

        if (password !== confirmPassword)
          errors.confirmPassword =
            "Les deux mots de passe ne correspondent pas";

        // // Check if username / email exists
        // const userByUsername = await User.findOne({ where: { username } })
        // const userByEmail = await User.findOne({ where: { email } })

        // if (userByUsername) errors.username = 'Username is taken'
        // if (userByEmail) errors.email = 'Email is taken'

        if (Object.keys(errors).length > 0) {
          throw errors;
        }

        // Hash password
        password = await bcrypt.hash(password, 6);

        // Create user
        const user = await User.create({
          username,
          email,
          password,
        });

        // Return user
        return user;
      } catch (err) {
        console.log(err);
        if (err.name === "SequelizeUniqueConstraintError") {
          err.errors.forEach(
            (e) => (errors[e.path] = `Le nom d'utilisateur est déjà utilisé`)
          );
        } else if (err.name === "SequelizeValidationError") {
          err.errors.forEach((e) => (errors[e.path] = e.message));
        }
        throw new UserInputError("Mauvaise saise", { errors });
      }
    },
  },
};
