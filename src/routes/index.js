const express = require("express");

const router = express.Router();

// Controller
const {
    addUser,
    getUsers,
    deleteUser,
    getUser,
    updateUser,
    getUsersByPayment,
    editUserDonate,
    getUsersByPaymentOne
} = require("../controllers/user");

const {
    addFund,
    updateFund,
    deleteFund,
    getFundsUserDonate,
    getFundsUserDonateOne
} = require("../controllers/fund")

const {
    addDonate,
    getDonate,
    getDonateFund,
    getDonates,
    updateDonate,
    deleteDonate
} = require("../controllers/payment")

const {
    register,
    login,
    checkAuth
} = require("../controllers/auth")

// const { auth } = require("../../middlewares/auth");

const { auth } = require("../../middlewares/auth")
const { uploadFile } = require("../../middlewares/uploadFile")

// Route User
router.post("/adduser", addUser);
router.get("/getusers", getUsers);
router.get("/getuser/:id", getUser);
router.put("/updateuser/:id", updateUser);
router.delete("/deleteuser/:id", deleteUser);


router.put("/edituserdonate/:fundId/:userId", editUserDonate); //req done
router.get("/getpaymentusers", getUsersByPayment); //
router.get("/getpaymentusersone/:id", getUsersByPaymentOne); //

// route Fund
router.post("/addfund", uploadFile("image"), addFund); //req done
router.put("/updatefund/:id", uploadFile("image"), updateFund); //req done
router.delete("/deletefund/:id", deleteFund); //req done

router.get("/getfundsuserdonateone/:id", getFundsUserDonateOne); // req done
router.get("/getfundsuserdonate", getFundsUserDonate); //req done

// route payment
router.post("/adddonate", uploadFile("image"), addDonate);
router.get("/getdonates", getDonates);
router.get("/getdonate/:id", getDonate);
router.put("/updatedonate/:id", updateDonate);
router.delete("/deleteDonate/:id", deleteDonate)

router.get("/getdonatefund", getDonateFund);

// route auth
router.post("/register", register) //req done
router.post("/login", login) // req done
router.get("/check-auth", checkAuth);

module.exports = router;