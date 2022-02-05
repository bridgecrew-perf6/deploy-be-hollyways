'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class user extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {

        user.hasMany(models.payment, {
            as: "payment",
            foreignKey: {
                name: "userId"
            }
        })

        user.belongsToMany(models.fund, {
            as: "fund",
            through: {
                model: "payments",
                as: "payment"
            },
            foreignKey: "userId",
            // foreignKey: "userId"
        })

        // user.hasMany(models.chat, {
        //     as: "senderMessage",
        //     foreignKey: {
        //     name: "idSender",
        //     },
        // });
        // user.hasMany(models.chat, {
        //     as: "recipientMessage",
        //     foreignKey: {
        //     name: "idRecipient",
        //     },
        // });
    }
  };
  user.init({
    fullName: DataTypes.STRING,
    email: DataTypes.STRING,
    password: DataTypes.STRING,
    status: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'user',
  });
  return user;
};