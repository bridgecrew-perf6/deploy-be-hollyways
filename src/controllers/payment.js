const { payment, user, fund } = require("../../models")

exports.addDonate = async (req, res) => {
    try {

        const { ...data } = req.body
        // return res.send(data)

        const createDonate = await payment.create({
            ...data,
            proofAttachment: req.file.filename,
        })

        dataDonate = JSON.parse(JSON.stringify(createDonate))


        res.status(200).send({
            status: "success",
            data: {
                ...dataDonate,
                image : dataDonate.image
            }
        })

    } catch (error) {
        console.log(error)
        res.send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getDonates = async (req, res) => {
    try {
        const showDonate = await payment.findAll({
            attributes: {
                exclude: ['fundId' ,'createdAt', 'updatedAt']
            }
        })

        res.send({
            status: "success",
            showDonate
        })

    } catch (error) {
        console.log(error)
        res.send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.getDonateFund = async (req, res) => {
    try {
        const showDonate = await payment.findAll({
            include: {
                model: Fund,
                as: "fund",
                attributes: {
                    exclude: ['createdAt', 'updatedAt']
                }
            },
            attributes: {
                exclude: ['createdAt', 'updatedAt']
            }
        })

        res.send({
            status: "success",
            showDonate
        })

    } catch (error) {
        console.log(error)
        res.send({
            status: "failed",
            message: "server error"
        })
    }
}


exports.getDonate = async(req, res) => {
    try {
        const { id } = req.params

        const dataDonate = await payment.findOne({
            where: {
                id
            },
            attributes: {
                exclude: ['createdAt', 'updatedAt']
            }
        })

        res.send({
            status: "success",
            dataDonate
        })

    } catch (error) {
        res.send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.deleteDonate = async (req, res) => {
    try {
        const {id} = req.params

        await payment.destroy({
            where: {
                id
            }
        })

        res.send({
            status: "success",
            message: `Delete Donate id = ${id} Successfuly`
        })

    } catch (error) {
        res.send({
            status: "failed",
            message: "server error"
        })
    }
}

exports.updateDonate = async (req, res) => {
    try {
        const { id } = req.params
        const newDonate = req.body

        await payment.update(newDonate, {
            where: {
                id
            }
        })

        res.send({
            status: "success",
            message: `Update data user id ${id} Successfuly`,
            data: newDonate
        })

    } catch (error) {
        console.log(error)
        res.send({
            status: 'failed',
            message: 'Server Error'
        })
    }
}