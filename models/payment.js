'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class payment extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {

        payment.belongsTo(models.user, {
            as: "user",
            foreignKey: {
                name: "userId"
            }
        })

        payment.belongsTo(models.fund, {
            as: "fund",
            foreignKey: {
                name: "fundId"
            }
        })
    }
  };
  payment.init({
    donateAmount: DataTypes.INTEGER,
    status: DataTypes.STRING,
    proofAttachment: DataTypes.STRING,
    userId: DataTypes.INTEGER,
    fundId: DataTypes.INTEGER,

  }, {
    sequelize,
    modelName: 'payment',
  });
  return payment;
};