const { user, fund, payment } = require("../../models")
// const { updateDonate } = require("./payment")

exports.addUser = async (req, res) => {
    try {
        const dataUser = req.body
        const createdUser = await user.create(dataUser)

        res.status(200).send({
            status: "success",
            createdUser
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getUsers = async (req, res) => {
    try {
        const showUsers = await user.findAll({
            attributes: {
                exclude: ['password', 'createdAt', 'updatedAt']
            }
        })

        res.status(200).send({
            status: "success",
            showUsers
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getUsersByPayment = async(req, res) => {
    try {
        const showUsers = await user.findAll({
            include: [
                {
                    model: payment,
                    as: "payment",
                    attributes: {
                        exclude: ['createdAt', 'updatedAt']
                    },
                    model: fund,
                    as: "fund",
                    attributes: {
                        exclude: ['createdAt', 'updatedAt']
                    },
                },
            ],
            attributes: {
                exclude: ['password', 'status', 'createdAt', 'updatedAt']
            }
        })

        res.status(200).send({
            status: "success",
            showUsers
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getUsersByPaymentOne = async(req, res) => {
    try {
        const { id } = req.params

        const showUsers = await user.findAll({
            where: {
                id
            },
            include: [
                {
                    model: payment,
                    as: "payment",
                    attributes: {
                        exclude: ['createdAt', 'updatedAt']
                    },
                    model: fund,
                    as: "fund",
                    attributes: {
                        exclude: ['createdAt', 'updatedAt']
                    },
                },
            ],
            attributes: {
                exclude: ['password', 'status', 'createdAt', 'updatedAt']
            }
        })

        res.status(200).send({
            status: "success",
            showUsers
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getUser = async(req, res) => {
    try {
        const { id } = req.params

        const dataUuser = await user.findOne({
            where: {
                id
            },
            attributes: {
                exclude: ['password', 'createdAt', 'updatedAt']
            }
        })

        res.status(200).send({
            status: "success",
            dataUuser
        })

    } catch (error) {
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params

        await user.destroy({
            where: {
                id
            }
        })

        res.status(200).send({
            status: "success",
            message: `Delete User id = ${id} Successfuly`
        })

    } catch (error) {
        res.status(500).send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params
        const newUser = req.body

        await user.update(newUser, {
            where: {
                id
            }
        })

        res.status(200).send({
            status: "success",
            message: `Update data user id ${id} Successfuly`,
            data: newUser
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: 'Server Error'
        })
    }
}

exports.editUserDonate = async (req, res) => {
    try {
        const { fundId, userId } = req.params
        const statusPayment = req.body;

        await payment.update({status: 'success'}, {
            where: {
                fundId: fundId,
                userId: userId
            },
            attributes: {
                exclude : ["createdAt", "updatedAt"]
            }

        })

        let fundData = await fund.findOne({
            include: {
                model: user,
                as: "userDonate",
                through: {
                    model: payment,
                    as: "payment",
                    attributes: {
                        exclude: ["userId", "fundId", "createdAt", "updatedAt"]
                    },
                },
                attributes: {
                    exclude: ["password", "status", "createdAt", "updatedAt"]
                }
            },
            where: {
                id: fundId
            },
            attributes: {
                exclude: ["adminId", "createdAt", "updatedAt"]
            }
        })

        res.status(200).send({
            status: "success",
            message: 'Update Successfully',
            fundData
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "failed",
            message: 'Server Error'
        })
    }
}