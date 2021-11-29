const jwt = require('jsonwebtoken');
const tokenModel = require('../models/token.model');

class TokenService {
  generateTokens(payload) {
    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_TOKEN, {expiresIn: '15s'});
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_TOKEN, {expiresIn: '30d'});

    return {
      accessToken,
      refreshToken
    }
  }

  async saveToken(userId, refreshToken) {
    const tokenData = await tokenModel.findOne({ user: userId });
    if (tokenData) {
      tokenData.refreshToken = refreshToken;
      return tokenData.save();
    }
    const token = await tokenModel.create({ user: userId, refreshToken });
    return token;
  }

  async removeToken(refreshToken) {
    const token = await tokenModel.deleteOne({ refreshToken });
    return token;
  }

  async findToken(refreshToken) {
    const token = await tokenModel.findOne({ refreshToken });
    return token;
  }

  validateAccessToken(token) {
    try {
      const tokenData = jwt.verify(token, process.env.JWT_ACCESS_TOKEN);
      return tokenData;
    } catch(e) {
      return null;
    }
  }

  validateRefreshToken(token) {
    try {
      const tokenData = jwt.verify(token, process.env.JWT_REFRESH_TOKEN);
      return tokenData;
    } catch(e) {
      return null;
    }
  }
}

module.exports = new TokenService();