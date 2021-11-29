const { hash, verify } = require('argon2');
const uuid = require('uuid');

const UserModel = require('../models/user.model');
const mailService = require('./mail.service');
const tokenService = require('./token.service');
const UserDto = require('../dtos/user.dto');
const ApiError = require('../exceptions/api-error');

class UserService {
  async registration(email, password) {
    const candidate = await UserModel.findOne({ email });
    if (candidate) {
      throw ApiError.BadRequest(`The user with the email address ${candidate.email} already exist`);
    }
    const hashPassword = await hash(password);
    const activationLink = uuid.v4();

    const user = await UserModel.create({ email, password: hashPassword, activationLink });

    await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`);

    const userDto = new UserDto(user);
    const tokens = tokenService.generateTokens({...userDto});
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto
    }
  }

  async activate(activateLink) {
    const user = await UserModel.findOne({ activateLink });
    if (!user) {
      throw ApiError.BadRequest('Invalid activation link');
    }
    user.isActivated = true;
    await user.save();
  }

  async login(email, password) {
    const user = await UserModel.findOne({ email });
    if (!user) {
      throw ApiError.BadRequest('User not found');
    }

    const isCorrectPassword = await verify(user.password, password);

    if (!isCorrectPassword) {
      throw ApiError.BadRequest('Invalid password');
    }

    const userDto = new UserDto(user);
    const tokens = tokenService.generateTokens({...userDto});
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      tokens,
      user: userDto
    }
  }

  async logout(refreshToken) {
    const token = await tokenService.removeToken(refreshToken);
    return token;
  }

  async refresh(refreshToken) {
    if (!refreshToken) {
      throw ApiError.UnauthorizedError();
    }
    const userData = tokenService.validateRefreshToken(refreshToken);
    const tokenFromDb = await tokenService.findToken(refreshToken);
    if (!userData && !tokenFromDb) {
      throw ApiError.UnauthorizedError();
    }
    const user = await UserModel.findById(userData.id);
    const userDto = new UserDto(user);
    const tokens = tokenService.generateTokens({...userDto});
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      tokens,
      user: userDto
    }
  }

  async getAllUsers() {
    const users = await UserModel.find({});
    return users;
  }
}

module.exports = new UserService();